// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Command flareover is the CLI for the deterministic Cloudflare → EU-self-hosted
// migration engine. Its verbs walk the migration end to end:
//
//	assess   read-only: classify a Cloudflare zone snapshot (AUTO/ASK/MANUAL)
//	prepare  generate artifacts (Caddyfile, WAF, PowerDNS zone, egress, mesh); --validate
//	doctor   read-only pre-flight: is every target reachable/authorized/configured?
//	provision  stand the target up via APIs (PowerDNS zone + DNSSEC, CertMate DNS-01)
//	present  parity gate: probe the live edge vs the staged edge
//	execute  orchestrate the phases live up to the gated cutover
//	guard    failguards: health monitoring + rollback/failover trigger
//
// Plus zones/extract (live Cloudflare read), resolve (ASK → decisions.lock),
// cost, and storage (R2/S3 → MinIO). Every target adapter has been exercised
// against a real running service, not just mocks.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fabriziosalmi/flareover/internal/classify"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/cost"
	"github.com/fabriziosalmi/flareover/internal/dnstarget"
	"github.com/fabriziosalmi/flareover/internal/doctor"
	"github.com/fabriziosalmi/flareover/internal/guard"
	"github.com/fabriziosalmi/flareover/internal/objstore"
	"github.com/fabriziosalmi/flareover/internal/parity"
	"github.com/fabriziosalmi/flareover/internal/plan"
	"github.com/fabriziosalmi/flareover/internal/provider"
	"github.com/fabriziosalmi/flareover/internal/render"
	"github.com/fabriziosalmi/flareover/internal/report"
	"github.com/fabriziosalmi/flareover/internal/runbook"
	"github.com/fabriziosalmi/flareover/internal/safeio"
	"github.com/fabriziosalmi/flareover/internal/stack"
	"github.com/fabriziosalmi/flareover/internal/target"
	"github.com/fabriziosalmi/flareover/internal/target/certmate"
	"github.com/fabriziosalmi/flareover/internal/target/mesh"
	"github.com/fabriziosalmi/flareover/internal/target/spm"
	"github.com/fabriziosalmi/flareover/internal/validate"
)

const usage = `flareover: escape Cloudflare, deterministically, toward EU-sovereign infrastructure.

USAGE
  flareover <phase> [args]
  flareover version           Print the build version.

PHASES
  zones                     List every zone the token can see (account-scoped
                            read-only token migrates any/all of them).
  extract <domain|zone-id>  Read a live Cloudflare zone (read-only API) into a
                            snapshot JSON. Needs CLOUDFLARE_API_TOKEN in the env.
  assess <snapshot.json>    Classify a Cloudflare zone snapshot into an honest
                            AUTO/ASK/MANUAL coverage report.
  resolve <snapshot.json>   Walk the ASK questions into a decisions.lock
                            (interactive on a tty; --defaults / --merge <file>).
  cost <snapshot.json>      Estimate Cloudflare tier/add-on cost vs a flat EU
                            sovereign stack (--vps <eur/mo> to override).
  prepare <snapshot.json>   Generate the target-stack artifacts (Caddyfile,
                            caddy-waf rules, PowerDNS zone) for the AUTO plus
                            answered-ASK surface.
  provision ...             Stand up the target via APIs (DNS zone + DNSSEC,
                            CertMate DNS-01 certs). --pdns-url (PowerDNS), or
                            --dns scaleway|ovh|gandi|leaseweb|hetzner|route53|
                            clouddns|azure / --certmate-url.
  present ...               Parity gate: live edge vs staged edge (--after-addr).
  execute ...               Orchestrate the phases live up to the gated cutover.
                            Stops on MANUAL items unless --accept-manual.
  storage <buckets.json>    Migrate object storage (R2/S3) → self-hosted MinIO
                            (default), or managed EU S3: --dest scaleway [--region
                            fr-par|nl-ams|pl-waw|it-mil] / --dest ovh [--region
                            gra|sbg|de|waw] / --dest contabo [--region eu2] /
                            --dest aruba --minio-endpoint <service-point-url>.
                            Emits an rclone data-copy plan too.
  guard --url ...           Failguards watchdog: health-watch + rollback/failover
                            trigger. See GUARD FLAGS.
  doctor ...                Read-only pre-flight: is every target reachable,
                            authorized, and configured? GO/NO-GO before provision.
  providers                 List EU edge providers with their honest sovereignty
                            tier (EU-owned vs US-operator/EU-region).

DOCTOR FLAGS
  --pdns-url  (+ PDNS_API_KEY env)   probe the PowerDNS API + auth
  --certmate-url (+ CERTMATE_TOKEN)  probe CertMate health + DNS-provider config
  --minio-endpoint <url>             probe MinIO/S3 reachability
  --spm-url <url>                    probe secure-proxy-manager readiness
  --check-caddy                      check the local caddy build (caddy-waf + souin)

ASSESS FLAGS
  --md      emit the report as Markdown (migration-report fragment)
  --json    emit the raw findings as JSON
  --html    emit a self-contained, shareable HTML coverage report

GUARD FLAGS
  --url <url>            the migrated endpoint to health-check (required)
  --expect-status <code> HTTP status that means healthy (default 200)
  --interval <dur>       time between checks (default 30s)
  --fails <n>            consecutive failures before the trigger fires (default 3)
  --on-unhealthy "<cmd>" the rollback/failover command; runs in its own process
                         group, so stopping the watch never interrupts it
  --once                 run a single check and exit (CI health gate)
  --keep-watching        keep watching after the trigger fires, instead of exiting
  --log-json             one JSON record per event, for shipping to a log system

PREPARE FLAGS
  --decisions <file>   JSON map of ASK question id -> answer (decisions.lock)
  --edge-ip <ip>       public IP of the new Caddy edge (proxied records repoint here)
  --ca <name>          default cert CA: letsencrypt (default) | actalis
  --origin-ca <path>   PEM CA Caddy trusts to verify the origin when SSL was
                       Full (strict) and you answered origin-verify=verify with a
                       private replacement origin cert (→ tls_trusted_ca_certs).
                       Omit if the replacement origin cert is publicly trusted.
  --stack <id>         target stack profile (default: caddy)
  --dns <id>           authoritative DNS target: powerdns (default, self-hosted),
                       bunny, or managed scaleway / ovh / gandi / leaseweb / hetzner
                       (EU-owned) · route53 / clouddns / azure (AWS/Google/Microsoft,
                       US-operated, NOT sovereign). Apply live: "provision --dns
                       <id>", creds in env.
  --out <dir>          write artifacts under <dir> (default: stdout preview)
  --validate           prove the generated Caddyfile + zone parse (caddy validate)
  --rotate-mesh-keys   mint NEW WireGuard keys instead of reusing the ones already
                       under <out>/mesh. Breaks a deployed tunnel until BOTH ends
                       are redeployed; without it a re-run is byte-identical.
  --mesh-edge [name=]<host:port>  sovereign WireGuard tunnel to keep an existing
                       (e.g. on-prem) origin unchanged. Repeat for an HA edge
                       front: --mesh-edge hetzner=5.9.1.1:51820 --mesh-edge aws=18.2.3.4:51820
  --edge-provider <key>  emit a cloud-init per edge to boot it on that provider
                       (see "flareover providers"); requires --mesh-edge
`

// version is stamped at build time via -ldflags "-X main.version=…" (goreleaser
// sets it from the git tag). It stays "dev" for `go run` and local builds.
var version = "dev"

// rootCtx is cancelled when the process is asked to stop. Every phase takes a
// context and honours it — extractors, provisioners, the parity prober, the
// guard loop — but until this existed the CLI handed them all
// context.Background(), so the cancellation path each of them implements was
// unreachable and a signal killed the process mid-operation instead of
// unwinding it. guard.Watch's ctx.Done() branch was, literally, dead code.
var rootCtx = context.Background()

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rootCtx = ctx
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("flareover %s\n", version)
		return
	case "zones":
		os.Exit(cmdZones(os.Args[2:]))
	case "extract":
		os.Exit(cmdExtract(os.Args[2:]))
	case "assess":
		os.Exit(cmdAssess(os.Args[2:]))
	case "resolve":
		os.Exit(cmdResolve(os.Args[2:]))
	case "cost":
		os.Exit(cmdCost(os.Args[2:]))
	case "storage":
		os.Exit(cmdStorage(os.Args[2:]))
	case "prepare":
		os.Exit(cmdPrepare(os.Args[2:]))
	case "provision":
		os.Exit(cmdProvision(os.Args[2:]))
	case "present":
		os.Exit(cmdPresent(os.Args[2:]))
	case "execute":
		os.Exit(cmdExecute(os.Args[2:]))
	case "guard":
		os.Exit(cmdGuard(os.Args[2:]))
	case "doctor":
		os.Exit(cmdDoctor(os.Args[2:]))
	case "providers":
		os.Exit(cmdProviders(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "flareover: unknown phase %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdAssess(args []string) int {
	var path string
	var asMarkdown, asJSON, asHTML bool
	for _, a := range args {
		switch a {
		case "--md":
			asMarkdown = true
		case "--json":
			asJSON = true
		case "--html":
			asHTML = true
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover assess: unknown flag %q\n", a)
				return 2
			}
			path = a
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "flareover assess: need a snapshot JSON path")
		return 2
	}

	snap, err := loadSnapshot(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover assess: %v\n", err)
		return 1
	}

	rep := classify.Classify(snap)

	switch {
	case asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "flareover assess: %v\n", err)
			return 1
		}
	case asHTML:
		fmt.Print(rep.HTML())
	case asMarkdown:
		fmt.Print(rep.Markdown())
	default:
		fmt.Print(render.Assess(rep, render.Enabled(os.Stdout)))
	}

	// Exit non-zero when human attention is required, so CI/automation can gate.
	c := rep.Counts()
	if c[report.Manual] > 0 {
		return 10
	}
	if c[report.Ask] > 0 {
		return 11
	}
	return 0
}

// cmdResolve walks the ASK findings and records a decision for each, producing a
// decisions.lock. Interactive on a terminal (prompts one bounded yes/no or value
// at a time); non-interactive it applies the conservative default. Merges an
// existing decisions file so it is re-runnable and reviewable in git.
func cmdResolve(args []string) int {
	var snapPath, outPath, mergePath string
	var useDefaults bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--defaults":
			useDefaults = true
		case "--decisions", "--merge":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "flareover resolve: %s needs a value\n", a)
				return 2
			}
			i++
			if a == "--decisions" {
				outPath = args[i]
			} else {
				mergePath = args[i]
			}
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover resolve: unknown flag %q\n", a)
				return 2
			}
			snapPath = a
		}
	}
	if snapPath == "" {
		fmt.Fprintln(os.Stderr, "flareover resolve: need a snapshot JSON path")
		return 2
	}
	snap, err := loadSnapshot(snapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover resolve: %v\n", err)
		return 1
	}
	decisions, err := loadDecisions(mergePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover resolve: %v\n", err)
		return 1
	}

	rep := classify.Classify(snap)
	interactive := render.IsTTY(os.Stdin) && !useDefaults
	reader := bufio.NewReader(os.Stdin)
	answered, pending := 0, 0

	for _, f := range rep.Sorted() {
		if f.Verdict != report.Ask || f.Question == nil {
			continue
		}
		q := f.Question
		if v, ok := decisions[q.ID]; ok && strings.TrimSpace(v) != "" {
			continue // already decided (merge)
		}
		var ans string
		if interactive {
			hint := ""
			if q.Default != "" {
				hint = " (default " + q.Default + ")"
			}
			fmt.Fprintf(os.Stderr, "\n%s %s\n  %s [%s]%s: ", f.Kind, f.Name, q.Prompt, strings.Join(q.Options, "/"), hint)
			line, _ := reader.ReadString('\n')
			ans = strings.TrimSpace(line)
			if ans == "" {
				ans = q.Default
			}
		} else {
			ans = q.Default
		}
		if strings.TrimSpace(ans) == "" {
			pending++ // no default and no answer (e.g. an origin) → stays ASK
			continue
		}
		decisions[q.ID] = ans
		answered++
	}

	body, _ := json.MarshalIndent(decisions, "", "  ")
	body = append(body, '\n')
	fmt.Fprintf(os.Stderr, "resolved %d, %d still pending (need a value)\n", answered, pending)
	if outPath == "" {
		if _, err := os.Stdout.Write(body); err != nil {
			fmt.Fprintf(os.Stderr, "flareover resolve: writing to stdout: %v\n", err)
			return 1
		}
		return 0
	}
	if err := safeio.WriteFile(outPath, body, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "flareover resolve: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return 0
}

func cmdZones(args []string) int {
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "flareover zones: set CLOUDFLARE_API_TOKEN (account-scoped read-only)")
		return 2
	}
	client := cf.NewClient(token)
	zones, err := client.ListZones(rootCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover zones: %v\n", err)
		return 1
	}
	if len(zones) == 0 {
		fmt.Fprintln(os.Stderr, "flareover zones: token sees no zones (scope too narrow?)")
		return 1
	}
	fmt.Fprintf(os.Stderr, "%d zone(s) visible to this token:\n", len(zones))
	for _, z := range zones {
		fmt.Printf("  %-30s %-10s %s  (%s)\n", z.Name, z.Status, z.ID, z.Account.Name)
	}
	return 0
}

func cmdExtract(args []string) int {
	var zoneRef, outPath string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--out":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "flareover extract: --out needs a value")
				return 2
			}
			i++
			outPath = args[i]
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover extract: unknown flag %q\n", a)
				return 2
			}
			zoneRef = a
		}
	}
	if zoneRef == "" {
		fmt.Fprintln(os.Stderr, "flareover extract: need a domain or zone id")
		return 2
	}
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "flareover extract: set CLOUDFLARE_API_TOKEN (scoped Zone:Read, DNS:Read, WAF:Read)")
		return 2
	}

	client := cf.NewClient(token)
	client.AccountID = os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	snap, err := client.Extract(rootCtx, zoneRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover extract: %v\n", err)
		return 1
	}

	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover extract: %v\n", err)
		return 1
	}
	body = append(body, '\n')

	for _, w := range client.Warnings {
		fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
	}
	fmt.Fprintf(os.Stderr, "flareover extract (%s): %d DNS, %d rulesets, %d managed, %d page rules, %d workers\n",
		snap.Zone.Name, len(snap.DNSRecords), len(snap.Rulesets), len(snap.ManagedRules), len(snap.PageRules), len(snap.Workers))

	if outPath == "" || outPath == "-" {
		if _, err := os.Stdout.Write(body); err != nil {
			fmt.Fprintf(os.Stderr, "flareover extract: writing to stdout: %v\n", err)
			return 1
		}
		return 0
	}
	if err := safeio.WriteFile(outPath, body, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "flareover extract: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return 0
}

func cmdCost(args []string) int {
	var path string
	var vps float64
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--vps":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "flareover cost: --vps needs a value")
				return 2
			}
			i++
			fmt.Sscanf(args[i], "%f", &vps)
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover cost: unknown flag %q\n", a)
				return 2
			}
			path = a
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "flareover cost: need a snapshot JSON path")
		return 2
	}
	snap, err := loadSnapshot(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover cost: %v\n", err)
		return 1
	}
	rep := cost.Estimate(snap, cost.Options{EUStackVPSMonthly: vps})
	fmt.Print(render.Cost(rep, render.Enabled(os.Stdout)))
	return 0
}

func cmdStorage(args []string) int {
	var path, decisionsPath, outDir, endpoint, alias, s3Endpoint, s3Region, dest, region string
	var extractR2, extractS3 bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--extract-r2":
			extractR2 = true
		case "--extract-s3":
			extractS3 = true
		case "--decisions", "--out", "--minio-endpoint", "--minio-alias", "--s3-endpoint", "--s3-region", "--dest", "--region":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "flareover storage: %s needs a value\n", a)
				return 2
			}
			i++
			switch a {
			case "--decisions":
				decisionsPath = args[i]
			case "--out":
				outDir = args[i]
			case "--minio-endpoint":
				endpoint = args[i]
			case "--minio-alias":
				alias = args[i]
			case "--s3-endpoint":
				s3Endpoint = args[i]
			case "--s3-region":
				s3Region = args[i]
			case "--dest":
				dest = args[i]
			case "--region":
				region = args[i]
			}
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover storage: unknown flag %q\n", a)
				return 2
			}
			path = a
		}
	}
	var snap objstore.Snapshot
	if extractS3 {
		ak, sk := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
		if ak == "" || sk == "" || s3Endpoint == "" {
			fmt.Fprintln(os.Stderr, "flareover storage --extract-s3: set --s3-endpoint (+ --s3-region) and AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY")
			return 2
		}
		var err error
		snap, err = objstore.ExtractS3(rootCtx, objstore.S3Config{
			Endpoint: s3Endpoint, Region: s3Region, AccessKey: ak, SecretKey: sk,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "extracted %d S3 bucket(s)\n", len(snap.Buckets))
	} else if extractR2 {
		token := os.Getenv("CLOUDFLARE_API_TOKEN")
		acct := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
		if token == "" || acct == "" {
			fmt.Fprintln(os.Stderr, "flareover storage --extract-r2: set CLOUDFLARE_API_TOKEN (R2 Storage:Read) + CLOUDFLARE_ACCOUNT_ID")
			return 2
		}
		var err error
		snap, err = objstore.ExtractR2(rootCtx, token, acct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "extracted %d R2 bucket(s)\n", len(snap.Buckets))
	} else {
		if path == "" {
			fmt.Fprintln(os.Stderr, "flareover storage: need a snapshot JSON, or --extract-r2 for a live R2 account")
			return 2
		}
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(b, &snap); err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
	}
	rep := objstore.Classify(snap)
	fmt.Print(rep.Text())

	if outDir != "" {
		decisions, err := loadDecisions(decisionsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
		if dest != "" && dest != "minio" && dest != "scaleway" && dest != "ovh" && dest != "contabo" && dest != "aruba" {
			fmt.Fprintf(os.Stderr, "flareover storage: unknown --dest %q (want: minio | scaleway | ovh | contabo | aruba)\n", dest)
			return 2
		}
		if dest == "aruba" && endpoint == "" {
			fmt.Fprintln(os.Stderr, "flareover storage: --dest aruba needs --minio-endpoint <your Aruba Service Point URL> (Aruba's S3 endpoint is account-specific: copy it from the Object Storage account page; it is never guessed)")
			return 2
		}
		if dest == "scaleway" && region != "" && !objstore.ValidScalewayRegion(region) {
			fmt.Fprintf(os.Stderr, "flareover storage: unknown Scaleway --region %q (want one of: %s)\n", region, strings.Join(objstore.ScalewayRegions, ", "))
			return 2
		}
		if dest == "ovh" && region != "" && !objstore.ValidOVHStorageRegion(region) {
			fmt.Fprintf(os.Stderr, "flareover storage: unknown OVH --region %q (EU regions: %s)\n", region, strings.Join(objstore.OVHStorageRegions, ", "))
			return 2
		}
		if dest == "contabo" && region != "" && !objstore.ValidContaboStorageRegion(region) {
			fmt.Fprintf(os.Stderr, "flareover storage: unknown Contabo --region %q (EU regions: %s)\n", region, strings.Join(objstore.ContaboStorageRegions, ", "))
			return 2
		}
		arts := objstore.Generate(snap, objstore.GenOptions{
			MinIOAlias: alias, MinIOEndpoint: endpoint, Decisions: decisions, Dest: dest, Region: region,
		})
		// objstore.Artifact carries no Mode (its outputs have always been 0644);
		// widen it to the common shape so both phases share one writer.
		files := make([]target.Artifact, len(arts))
		for i, a := range arts {
			files[i] = target.Artifact{Path: a.Path, Content: a.Content, Mode: 0o644, Note: a.Note}
		}
		if err := writeArtifacts(outDir, files); err != nil {
			fmt.Fprintf(os.Stderr, "flareover storage: %v\n", err)
			return 1
		}
	}
	c := rep.Counts()
	if c[report.Manual] > 0 {
		return 10
	}
	if c[report.Ask] > 0 {
		return 11
	}
	return 0
}

// cmdExecute orchestrates the migration phases with a live progress display,
// up to and including the parity gate. The DNS flip itself is intentionally NOT
// performed here (it is your explicit, outward action) so execute runs the
// deterministic, safe phases live, proves the gate, and hands you the go/no-go.
func cmdExecute(args []string) int {
	var snapPath, decisionsPath, afterAddr string
	beforeScheme, afterScheme := "https", "https"
	var insecureAfter, acceptManual bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--insecure-after":
			insecureAfter = true
		case "--accept-manual":
			acceptManual = true
		case "--snapshot", "--decisions", "--after-addr", "--before-scheme", "--after-scheme":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "flareover execute: %s needs a value\n", a)
				return 2
			}
			i++
			switch a {
			case "--snapshot":
				snapPath = args[i]
			case "--decisions":
				decisionsPath = args[i]
			case "--after-addr":
				afterAddr = args[i]
			case "--before-scheme":
				beforeScheme = args[i]
			case "--after-scheme":
				afterScheme = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "flareover execute: unknown arg %q\n", a)
			return 2
		}
	}
	if snapPath == "" || afterAddr == "" {
		fmt.Fprintln(os.Stderr, "flareover execute: need --snapshot and --after-addr <host:port> (staged edge); --decisions recommended")
		return 2
	}
	snap, err := loadSnapshot(snapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover execute: %v\n", err)
		return 1
	}
	decisions, err := loadDecisions(decisionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover execute: %v\n", err)
		return 1
	}

	color := render.Enabled(os.Stdout)
	tty := render.IsTTY(os.Stdout)
	pr := render.NewProgress(os.Stdout, []string{
		"Assess", "Prepare", "Present · parity gate", "Cutover", "Failguards",
	}, color, tty)

	pr.Start(0)
	rep := classify.Classify(snap)
	c := rep.Counts()
	pr.Done(0, fmt.Sprintf("%d elements · %d AUTO / %d ASK / %d MANUAL",
		len(rep.Findings), c[report.Auto], c[report.Ask], c[report.Manual]))

	// A MANUAL item is a control the generated stack does not reproduce. This
	// verb orchestrates a cutover, so it stops here rather than counting them
	// into a progress line and carrying on: authorising a flip while an
	// unmigrated Zero-Trust policy or Worker is outstanding is the decision a
	// human has to make explicitly, with the list in front of them.
	if c[report.Manual] > 0 && !acceptManual {
		pr.Fail(0, fmt.Sprintf("%d MANUAL item(s): cutover not authorized", c[report.Manual]))
		printManual(rep, "execute")
		fmt.Fprintln(os.Stderr, "\n  Handle these by hand, or re-run with --accept-manual to proceed anyway.")
		return 10
	}

	pr.Start(1)
	built, err := plan.Build(snap, plan.Options{Decisions: decisions})
	if err != nil {
		pr.Fail(1, err.Error())
		return 1
	}
	profile, _ := stack.Profile("caddy")
	arts, _ := profile.Generate(built)
	pr.Done(1, fmt.Sprintf("%d sites · %d artifacts (caddy stack)", len(built.Sites), len(arts)))

	pr.Start(2)
	probes := parity.ProbesFromPlan(built)
	if len(probes) == 0 {
		pr.Fail(2, "no probes (answer origin ASK items in --decisions)")
		return 2
	}
	before := parity.Endpoint{Scheme: beforeScheme}
	after := parity.Endpoint{Scheme: afterScheme, DialOverride: afterAddr, Insecure: insecureAfter}
	prep, err := parity.NewComparer().Compare(rootCtx, before, after, probes)
	if err != nil {
		pr.Fail(2, err.Error())
		return 1
	}
	if !prep.Gate() {
		pr.Fail(2, fmt.Sprintf("%d probes · GATE FAIL: cutover blocked", len(prep.Results)))
		pr.PrintLine("")
		fmt.Print(render.Parity(prep, color))
		return 12
	}
	pr.Done(2, fmt.Sprintf("%d probes · GATE PASS", len(prep.Results)))

	pr.Start(3)
	pr.Done(3, "authorized: flip DNS to the EU edge (your explicit step)")

	pr.Start(4)
	pr.Done(4, "rollback armed: one command back to the source")

	pr.PrintLine("")
	pr.PrintLine("  Cutover is authorized by the gate. Flip DNS with your write-token script,")
	pr.PrintLine("  then re-run `present` against the live domain to confirm. Rollback stays ready.")
	return 0
}

func cmdPresent(args []string) int {
	var snapPath, decisionsPath, afterAddr string
	beforeScheme, afterScheme := "https", "https"
	var insecureAfter bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--insecure-after":
			insecureAfter = true
		case "--snapshot", "--decisions", "--after-addr", "--before-scheme", "--after-scheme":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "flareover present: %s needs a value\n", a)
				return 2
			}
			i++
			switch a {
			case "--snapshot":
				snapPath = args[i]
			case "--decisions":
				decisionsPath = args[i]
			case "--after-addr":
				afterAddr = args[i]
			case "--before-scheme":
				beforeScheme = args[i]
			case "--after-scheme":
				afterScheme = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "flareover present: unknown arg %q\n", a)
			return 2
		}
	}
	if snapPath == "" || afterAddr == "" {
		fmt.Fprintln(os.Stderr, "flareover present: need --snapshot and --after-addr <host:port> (staged edge).")
		fmt.Fprintln(os.Stderr, "The live edge (before) is reached via DNS for each host; the staged edge is dialed at --after-addr with the host's SNI.")
		return 2
	}

	snap, err := loadSnapshot(snapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover present: %v\n", err)
		return 1
	}
	decisions, err := loadDecisions(decisionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover present: %v\n", err)
		return 1
	}
	built, err := plan.Build(snap, plan.Options{Decisions: decisions})
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover present: %v\n", err)
		return 1
	}
	probes := parity.ProbesFromPlan(built)
	if len(probes) == 0 {
		fmt.Fprintln(os.Stderr, "flareover present: no probes (answer origin ASK questions in --decisions)")
		return 2
	}
	before := parity.Endpoint{Scheme: beforeScheme}
	after := parity.Endpoint{Scheme: afterScheme, DialOverride: afterAddr, Insecure: insecureAfter}
	rep, err := parity.NewComparer().Compare(rootCtx, before, after, probes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover present: %v\n", err)
		return 1
	}
	fmt.Print(render.Parity(rep, render.Enabled(os.Stdout)))
	if !rep.Gate() {
		return 12 // cutover blocked
	}
	return 0
}

// cmdProvision stands up the target infrastructure the plan describes (the
// PowerDNS zone and the CertMate certificates) via their APIs, with a live
// progress display. It writes only to your own target services (with your
// target credentials); it never touches the source or the registrar. This is
// the auto-provision step that closes the gap between "generate" and "done".
func cmdProvision(args []string) int {
	var snapPath, decisionsPath, nsList, edgeIP string
	var pdnsURL, cmURL, cmToken, ca, originCA, cmAccount, cmDNS, dnsTarget string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--pdns-key" || a == "--certmate-token" {
			fmt.Fprintf(os.Stderr, "flareover provision: %s is no longer accepted (it would expose the secret on argv). Set PDNS_API_KEY / CERTMATE_TOKEN in the environment instead\n", a)
			return 2
		}
		next := func() string { i++; return args[i] }
		if i+1 >= len(args) && strings.HasPrefix(a, "--") {
			fmt.Fprintf(os.Stderr, "flareover provision: %s needs a value\n", a)
			return 2
		}
		switch a {
		case "--snapshot":
			snapPath = next()
		case "--decisions":
			decisionsPath = next()
		case "--edge-ip":
			edgeIP = next()
		case "--nameservers":
			nsList = next()
		case "--dns":
			dnsTarget = next()
		case "--pdns-url":
			pdnsURL = next()
		case "--certmate-url":
			cmURL = next()
		case "--certmate-account":
			cmAccount = next()
		case "--certmate-dns":
			cmDNS = next()
		case "--ca":
			ca = next()
		case "--origin-ca":
			originCA = next()
		default:
			fmt.Fprintf(os.Stderr, "flareover provision: unknown arg %q\n", a)
			return 2
		}
	}
	// PowerDNS/CertMate secrets come from the environment only, never argv, like
	// every other backend, so they never leak via ps / /proc / shell history.
	cmToken = os.Getenv("CERTMATE_TOKEN")

	// DNS backend selection, resolved through the one registry `prepare` also
	// uses. Credential loading, presence checking and construction live beside
	// each provider in internal/dnstarget; this used to be eight providers'
	// worth of inline environment reading and validation, and it is most of why
	// this function measured cyclomatic complexity 131.
	dnsT, ok := dnstarget.Lookup(dnsTarget)
	if !ok {
		fmt.Fprintf(os.Stderr, "%v\n", dnstarget.UnknownError("provision", dnsTarget))
		return 2
	}
	// An explicit --dns naming a generate-only backend is a real request the
	// tool cannot honour; say so, rather than reporting it as unknown.
	if dnsTarget != "" && dnsT.GenerateOnly() {
		fmt.Fprintf(os.Stderr, "flareover provision: --dns %s is generate-only (%s has no mapped record API).\n"+
			"  Run `flareover prepare --dns %s --out <dir>` and apply the emitted script yourself.\n",
			dnsT.Key, dnsT.Label, dnsT.Key)
		return 2
	}

	wantDNS := dnsTarget != "" || pdnsURL != ""
	if snapPath == "" || (!wantDNS && cmURL == "") {
		fmt.Fprintf(os.Stderr, "flareover provision: need --snapshot and at least one of --pdns-url / --certmate-url / --dns %s\n",
			strings.Join(dnstarget.Keys(), "|"))
		return 2
	}
	if !dnsT.Sovereign {
		// Honest tier: never let a US-operated target pass as sovereign.
		fmt.Fprintf(os.Stderr, "flareover provision: NOTE: %s. For EU sovereignty: --dns scaleway|ovh|gandi|leaseweb|hetzner (or bunny via `prepare --dns bunny` + apply.sh).\n", dnsT.Label)
	}

	if ca == "" {
		ca = "letsencrypt"
	}
	snap, err := loadSnapshot(snapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover provision: %v\n", err)
		return 1
	}
	decisions, err := loadDecisions(decisionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover provision: %v\n", err)
		return 1
	}
	built, err := plan.Build(snap, plan.Options{Decisions: decisions, CA: ca, OriginCA: originCA, EdgeIP: edgeIP})
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover provision: %v\n", err)
		return 1
	}

	pr := render.NewProgress(os.Stdout, []string{"DNS zone", "Certificates (DNS-01)"},
		render.Enabled(os.Stdout), render.IsTTY(os.Stdout))
	ctx := rootCtx
	var dsRecords []string

	// DNS zone. One path for every backend: the registry hands back a
	// provisioner or an error naming exactly what is missing, and the optional
	// interfaces cover what only some backends can do.
	pr.Start(0)
	if !wantDNS {
		pr.Done(0, fmt.Sprintf("skipped (no --pdns-url / --dns %s)", strings.Join(dnstarget.Keys(), "|")))
	} else {
		dp, err := dnsT.NewProvisioner(dnstarget.Opts{PDNSURL: pdnsURL, Nameservers: splitCSV(nsList)})
		if err != nil {
			pr.Fail(0, fmt.Sprintf("--dns %s: %v", dnsT.Key, err))
			return 2
		}
		if err := dp.Provision(ctx, built.DNS); err != nil {
			pr.Fail(0, err.Error())
			return 1
		}
		detail := fmt.Sprintf("%d records (%s)", len(built.DNS.Records), dnsT.Label)
		if l, ok := dp.(dnstarget.NameserverLister); ok {
			if ns, err := l.Nameservers(ctx, built.DNS.Name); err == nil && len(ns) > 0 {
				detail += " · delegate NS at registrar: " + strings.Join(ns, ", ")
			}
		}
		if built.DNS.DNSSEC {
			if e, ok := dp.(dnstarget.DNSSECEnabler); ok {
				if ds, err := e.EnableDNSSEC(ctx, built.DNS.Name); err == nil {
					dsRecords = ds
					detail += fmt.Sprintf(", DNSSEC signed (%d DS)", len(ds))
				}
			} else if dnsT.DNSSECNote != "" {
				detail += " · DNSSEC: " + dnsT.DNSSECNote
			}
		}
		pr.Done(0, detail)
	}

	// CertMate
	pr.Start(1)
	if cmURL == "" {
		pr.Done(1, "skipped (no --certmate-url)")
	} else {
		reqs := certmate.PlanCerts(built, ca, cmAccount, cmDNS)
		c := certmate.NewClient(cmURL, cmToken)
		for _, rq := range reqs {
			if err := c.Issue(ctx, rq); err != nil {
				pr.Fail(1, fmt.Sprintf("%s: %v", rq.Domain, err))
				return 1
			}
		}
		pr.Done(1, fmt.Sprintf("%d cert request(s) via DNS-01 · CA %s", len(reqs), ca))
	}

	if len(dsRecords) > 0 {
		pr.PrintLine("")
		pr.PrintLine("  Publish these DS records at your registrar to complete DNSSEC:")
		for _, ds := range dsRecords {
			pr.PrintLine("    " + ds)
		}
	}
	return 0
}

// cmdGuard is the Failguards watchdog: it health-checks the migrated edge on an
// interval and, past a failure threshold, runs a trigger: typically the
// rollback (back to the source), or a flip to a warm standby (failover). The
// trigger is a shell command you supply, so the outward DNS write stays your
// explicit hook.
func cmdGuard(args []string) int {
	var url, onUnhealthy string
	expectStatus, fails := 200, 3
	interval := 30 * time.Second
	var once, logJSON, keepWatching bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--once":
			once = true
			continue
		case "--log-json":
			logJSON = true
			continue
		case "--keep-watching":
			keepWatching = true
			continue
		}
		if i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "flareover guard: %s needs a value\n", a)
			return 2
		}
		i++
		switch a {
		case "--url":
			url = args[i]
		case "--expect-status":
			// Parsed strictly. These used to go through fmt.Sscanf with the
			// error discarded, so `--expect-status 3O1` silently left the 200
			// default in place — and the guard then reported a healthy 301 site
			// as failing and ran the rollback trigger against it.
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 100 || n > 599 {
				fmt.Fprintf(os.Stderr, "flareover guard: --expect-status %q is not an HTTP status code (100-599)\n", args[i])
				return 2
			}
			expectStatus = n
		case "--interval":
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "flareover guard: --interval %q is not a positive duration (e.g. 30s, 2m)\n", args[i])
				return 2
			}
			interval = d
		case "--fails":
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				fmt.Fprintf(os.Stderr, "flareover guard: --fails %q is not a positive count\n", args[i])
				return 2
			}
			fails = n
		case "--on-unhealthy":
			onUnhealthy = args[i]
		default:
			fmt.Fprintf(os.Stderr, "flareover guard: unknown arg %q\n", a)
			return 2
		}
	}
	if url == "" {
		fmt.Fprintln(os.Stderr, "flareover guard: need --url <migrated-domain>; optional --on-unhealthy \"<rollback cmd>\", --interval, --fails, --once, --keep-watching, --log-json")
		return 2
	}

	color := render.Enabled(os.Stdout)
	green, red, dim, reset := "", "", "", ""
	if color {
		green, red, dim, reset = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
	}
	// emit writes one record per event. This is the only long-running verb, and
	// the only one whose output a human is not watching: a redirected guard log
	// used to be a stream of `15:04:05 ✓ healthy` lines carrying no date and no
	// indication of what was being watched, so two guards for two zones were
	// indistinguishable and a watch spanning midnight had ambiguous timestamps.
	emit := func(ev string, s guard.Status, extra map[string]any) {
		if logJSON {
			rec := map[string]any{
				"time": s.At.Format(time.RFC3339), "event": ev, "url": url,
				"healthy": s.Healthy, "consecutive_fails": s.ConsecutiveFails, "threshold": fails,
			}
			if s.Reason != "" {
				rec["reason"] = s.Reason
			}
			for k, v := range extra {
				rec[k] = v
			}
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
			return
		}
		ts := s.At.Format(time.RFC3339)
		switch {
		case ev == "healthy":
			fmt.Printf("  %s%s%s %s✓ healthy%s %s%s%s\n", dim, ts, reset, green, reset, dim, url, reset)
		case ev == "unhealthy":
			fmt.Printf("  %s%s%s %s✗ %s%s %s(%d/%d · %s)%s\n", dim, ts, reset, red, s.Reason, reset, dim, s.ConsecutiveFails, fails, url, reset)
		default:
			fmt.Printf("  %s%s%s %s%s%s %s%s%s\n", dim, ts, reset, red, ev, reset, dim, url, reset)
		}
	}
	statusReport := func(s guard.Status) {
		if s.Healthy {
			emit("healthy", s, nil)
		} else {
			emit("unhealthy", s, nil)
		}
	}
	onFail := func(reason string) error {
		now := guard.Status{At: time.Now(), Reason: reason, ConsecutiveFails: fails}
		emit("threshold-reached", now, nil)
		if onUnhealthy == "" {
			emit("trigger-skipped", now, map[string]any{"note": "no --on-unhealthy set; alerting only"})
			return nil
		}
		emit("trigger-running", now, map[string]any{"command": onUnhealthy})
		cmd := exec.Command("bash", "-c", onUnhealthy) // #nosec G204: the operator's own --on-unhealthy hook, by design
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		// Detach the trigger from this process's signal group. A Ctrl-C aimed at
		// the watchdog would otherwise also hit a rollback already in flight,
		// interrupting the very thing the guard exists to complete.
		detachProcessGroup(cmd)
		return cmd.Run()
	}

	// The watch ends for a reason, and the reason is worth recording: without a
	// closing record, a guard that stopped and a guard that is quietly healthy
	// produce the same (absent) output in a log nobody is tailing.
	end := func(ev string, extra map[string]any) {
		emit(ev, guard.Status{At: time.Now(), Healthy: true}, extra)
	}

	triggered, err := guard.Watch(rootCtx, guard.HTTPCheck(url, expectStatus), guard.Options{
		Interval: interval, FailThreshold: fails, OnUnhealthy: onFail, Report: statusReport,
		Once: once, KeepWatching: keepWatching,
	})
	if err != nil {
		end("watch-ended", map[string]any{"error": err.Error()})
		fmt.Fprintf(os.Stderr, "flareover guard: %v\n", err)
		return 1
	}
	if triggered {
		end("watch-ended", map[string]any{"note": "guard fired: rollback/failover triggered"})
		return 20
	}
	end("watch-ended", map[string]any{"note": "watch completed"})
	return 0
}

func cmdPrepare(args []string) int {
	var path, decisionsPath, edgeIP, ca, originCA, stackID, dnsTarget, outDir, blocklists, egressAllow, edgeProvider string
	var meshEdges []string
	var egressDeny, egressSSLBump, doValidate, rotateMeshKeys bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--egress-deny":
			egressDeny = true
			continue
		case "--egress-ssl-bump":
			egressSSLBump = true
			continue
		case "--validate":
			doValidate = true
			continue
		case "--rotate-mesh-keys":
			rotateMeshKeys = true
			continue
		}
		switch a {
		case "--decisions", "--edge-ip", "--ca", "--origin-ca", "--stack", "--dns", "--out", "--blocklists", "--egress-allow", "--mesh-edge", "--edge-provider":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "flareover prepare: %s needs a value\n", a)
				return 2
			}
			i++
			switch a {
			case "--decisions":
				decisionsPath = args[i]
			case "--edge-ip":
				edgeIP = args[i]
			case "--ca":
				ca = args[i]
			case "--origin-ca":
				originCA = args[i]
			case "--stack":
				stackID = args[i]
			case "--dns":
				dnsTarget = args[i]
			case "--out":
				outDir = args[i]
			case "--blocklists":
				blocklists = args[i]
			case "--egress-allow":
				egressAllow = args[i]
			case "--mesh-edge":
				meshEdges = append(meshEdges, args[i])
			case "--edge-provider":
				edgeProvider = args[i]
			}
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "flareover prepare: unknown flag %q\n", a)
				return 2
			}
			path = a
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "flareover prepare: need a snapshot JSON path")
		return 2
	}

	snap, err := loadSnapshot(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 1
	}
	decisions, err := loadDecisions(decisionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 1
	}
	profile, err := stack.Profile(stackID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 2
	}
	// The DNS target is orthogonal to the proxy profile. Resolved through the
	// one registry `provision` also uses, so the two verbs cannot advertise
	// different vocabularies — which is how `--dns bunny` came to be accepted
	// here and rejected there.
	dnsT, ok := dnstarget.Lookup(dnsTarget)
	if !ok {
		fmt.Fprintf(os.Stderr, "%v\n", dnstarget.UnknownError("prepare", dnsTarget))
		return 2
	}
	profile.DNS = dnsT.Generator

	var bl, egAllow []string
	if blocklists != "" {
		bl = strings.Split(blocklists, ",")
	}
	if egressAllow != "" {
		egAllow = strings.Split(egressAllow, ",")
	}
	// Classify before generating: the report drives both the MIGRATION.md
	// runbook and the MANUAL summary printed at the end, and computing it once
	// keeps the two from disagreeing.
	rep := classify.Classify(snap)
	built, err := plan.Build(snap, plan.Options{
		EdgeIP: edgeIP, CA: ca, OriginCA: originCA, Decisions: decisions, Blocklists: bl,
		EgressDeny: egressDeny, EgressAllow: egAllow, EgressSSLBump: egressSSLBump,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 1
	}
	arts, err := profile.Generate(built)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 1
	}
	if built.Egress != nil {
		arts = append(arts, spm.Generate(*built.Egress)...)
	}
	if len(meshEdges) > 0 {
		var edges []mesh.Edge
		for _, spec := range meshEdges {
			name, endpoint := "", spec
			if i := strings.Index(spec, "="); i >= 0 {
				name, endpoint = spec[:i], spec[i+1:]
			}
			edges = append(edges, mesh.Edge{Name: name, Endpoint: endpoint})
		}
		// Reuse the keys already on disk unless rotation was asked for. Without
		// this, every re-run mints keys no deployed peer recognises and the
		// atomic write replaces the only copy of the working ones.
		var meshKeys map[string]string
		if outDir != "" && !rotateMeshKeys {
			meshKeys, err = mesh.LoadKeys(outDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "flareover prepare: reading existing mesh keys: %v\n", err)
				return 1
			}
			if len(meshKeys) > 0 {
				fmt.Fprintf(os.Stderr, "  mesh: reusing %d existing key(s) from %s/mesh (use --rotate-mesh-keys to replace them)\n",
					len(meshKeys), outDir)
			}
		}
		if rotateMeshKeys {
			fmt.Fprintln(os.Stderr, "  mesh: --rotate-mesh-keys: generating NEW keys; redeploy every edge AND the origin together")
		}
		meshArts, err := mesh.GenerateWireGuard(mesh.Config{Edges: edges, Keys: meshKeys})
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
			return 1
		}
		arts = append(arts, meshArts...)
	}

	// Optional: emit a cloud-init per edge that boots the node from the artifacts
	// above, stamped with the chosen provider's sovereignty tier.
	if edgeProvider != "" {
		prov, ok := provider.Lookup(edgeProvider)
		if !ok {
			fmt.Fprintf(os.Stderr, "flareover prepare: unknown --edge-provider %q (see `flareover providers`)\n", edgeProvider)
			return 2
		}
		if len(meshEdges) == 0 {
			fmt.Fprintln(os.Stderr, "flareover prepare: --edge-provider needs at least one --mesh-edge (the edge's WireGuard config)")
			return 2
		}
		ciArts, err := edgeCloudInits(arts, prov)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
			return 1
		}
		arts = append(arts, ciArts...)
	}

	if doValidate {
		if code := validateArtifacts(arts); code != 0 {
			return code
		}
	}

	fmt.Fprintf(os.Stderr, "flareover prepare (%s [%s]): %d records, %d sites, %d WAF rules → %d artifacts\n",
		built.Zone, profile.ID, len(built.DNS.Records), len(built.Sites), len(built.WAF.CustomRules), len(arts))

	if outDir == "" {
		// Preview mode: print each artifact with its note.
		for _, a := range arts {
			fmt.Printf("\n===== %s =====\n", a.Path)
			if a.Note != "" {
				fmt.Printf("# note: %s\n", a.Note)
			}
			if _, err := os.Stdout.Write(a.Content); err != nil {
				fmt.Fprintf(os.Stderr, "flareover prepare: writing to stdout: %v\n", err)
				return 1
			}
		}
		return 0
	}
	// The runbook is part of the artifact set, not an afterthought: adding it
	// here means every file this command produces goes through one atomic,
	// path-contained writer instead of a second bare WriteFile at the end.
	paths := make([]string, len(arts))
	for i, a := range arts {
		paths[i] = a.Path
	}
	arts = append(arts, target.Artifact{
		Path:    "MIGRATION.md",
		Content: runbook.Generate(rep, built, paths),
		Mode:    0o644,
		Note:    "runbook + manual/ask items + cutover steps",
	})
	if err := writeArtifacts(outDir, arts); err != nil {
		fmt.Fprintf(os.Stderr, "flareover prepare: %v\n", err)
		return 1
	}

	// Same verdict gate `assess` and `storage` already apply. The artifacts are
	// written either way — they are the AUTO plus answered-ASK surface and they
	// are correct — but the exit code has to say that this migration is not
	// complete, because a MANUAL item is a control the generated stack does not
	// reproduce and somebody has to act on it by hand.
	c := rep.Counts()
	if c[report.Manual] > 0 {
		printManual(rep, "prepare")
		return 10
	}
	if c[report.Ask] > 0 {
		return 11
	}
	return 0
}

// printManual lists the MANUAL findings on stderr so the operator sees what the
// generated stack does not cover, without having to re-run `assess`.
func printManual(rep report.Report, phase string) {
	var manual []report.Finding
	for _, f := range rep.Sorted() {
		if f.Verdict == report.Manual {
			manual = append(manual, f)
		}
	}
	fmt.Fprintf(os.Stderr, "\nflareover %s: %d MANUAL item(s) are NOT covered by the generated stack:\n", phase, len(manual))
	for _, f := range manual {
		fmt.Fprintf(os.Stderr, "  ✋ %-14s %s\n     %s\n", f.Kind, f.Name, f.Rationale)
	}
}

// writeArtifacts writes a generated set under outDir. Every path is checked for
// containment before it is joined (an Artifact.Path carries snapshot-derived
// values, and filepath.Join cleans "../" rather than refusing it), and every
// file is written atomically so an interruption cannot leave a truncated
// Caddyfile or zone file that still parses.
func writeArtifacts(outDir string, arts []target.Artifact) error {
	for _, a := range arts {
		dst, err := safeio.SecureJoin(outDir, a.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := safeio.WriteFile(dst, a.Content, os.FileMode(a.Mode)); err != nil {
			return err
		}
		if a.Note != "" {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", a.Path, a.Note)
		} else {
			fmt.Fprintf(os.Stderr, "  %s\n", a.Path)
		}
	}
	return nil
}

// edgeCloudInits builds one cloud-init per edge from the already-generated
// Caddyfile + that edge's WireGuard config, so a node boots fully configured.
// Each edge's provider is resolved from its own name when that name is a known
// provider key (so an HA front spread across providers is stamped correctly);
// otherwise it falls back to fallback (the --edge-provider default).
func edgeCloudInits(arts []target.Artifact, fallback provider.Provider) ([]target.Artifact, error) {
	var caddyfile []byte
	for _, a := range arts {
		if strings.HasSuffix(a.Path, "Caddyfile") {
			caddyfile = a.Content
		}
	}
	if caddyfile == nil {
		return nil, fmt.Errorf("--edge-provider: no Caddyfile in the generated artifacts")
	}
	var out []target.Artifact
	for _, a := range arts {
		if !strings.HasPrefix(a.Path, "mesh/") || !strings.HasSuffix(a.Path, ".wg0.conf") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(a.Path, "mesh/"), ".wg0.conf")
		if name == "origin" {
			continue
		}
		prov := fallback
		if p, ok := provider.Lookup(name); ok {
			prov = p // the edge is named after its provider → stamp it correctly
		}
		dst := "edge/cloud-init.yaml"
		if name != "edge" {
			dst = "edge/cloud-init-" + name + ".yaml"
		}
		out = append(out, target.Artifact{
			Path:    dst,
			Content: provider.EdgeCloudInit(prov, caddyfile, a.Content),
			Mode:    0o600,
			Note:    fmt.Sprintf("cloud-init for edge %q on %s (%s): paste as instance user-data", name, prov.Name, prov.Exposure),
		})
		// API-driven providers also get a create script that boots the edge from
		// that cloud-init (the operator runs it: a paid server is never spun up
		// silently).
		ciBase := strings.TrimPrefix(dst, "edge/")
		emitCreate := func(suffix string, content []byte, where string) {
			script := "edge/create." + suffix + ".sh"
			if name != "edge" {
				script = "edge/create-" + name + "." + suffix + ".sh"
			}
			out = append(out, target.Artifact{
				Path:    script,
				Content: content,
				Mode:    0o755,
				Note:    fmt.Sprintf("create edge %q on %s from its cloud-init (paid server: review first)", name, where),
			})
		}
		switch prov.Key {
		case "scaleway":
			emitCreate("scaleway", provider.ScalewayInstanceScript(name, ciBase), "Scaleway Instances")
		case "ovh":
			emitCreate("ovh", provider.OVHInstanceScript(name, ciBase), "OVHcloud Public Cloud")
		}
	}
	return out, nil
}

// validateArtifacts proves the generated Caddyfile and PowerDNS zone actually
// parse. A broken artifact returns non-zero so a caller can gate on it; a check
// that could not run (no caddy on PATH) is reported as skipped, not a failure.
func validateArtifacts(arts []target.Artifact) int {
	failed := false
	for _, a := range arts {
		switch {
		case strings.HasSuffix(a.Path, "Caddyfile"):
			r := validate.Caddyfile(a.Content)
			switch {
			case r.Skipped():
				fmt.Fprintf(os.Stderr, "  validate %s: skipped: %s\n", a.Path, r.Detail)
			case r.OK:
				fmt.Fprintf(os.Stderr, "  validate %s: OK (%s): %s\n", a.Path, r.Ran, r.Detail)
			default:
				fmt.Fprintf(os.Stderr, "  validate %s: FAILED (%s):\n%s\n", a.Path, r.Ran, r.Detail)
				failed = true
			}
		case strings.HasSuffix(a.Path, ".zone"):
			if ok, problems := validate.Zone(a.Content); ok {
				fmt.Fprintf(os.Stderr, "  validate %s: OK (zone structure)\n", a.Path)
			} else {
				fmt.Fprintf(os.Stderr, "  validate %s: FAILED (zone structure):\n", a.Path)
				for _, p := range problems {
					fmt.Fprintf(os.Stderr, "      %s\n", p)
				}
				failed = true
			}
		}
	}
	if failed {
		fmt.Fprintln(os.Stderr, "flareover prepare: generated artifacts did not validate")
		return 1
	}
	return 0
}

// cmdDoctor runs the read-only pre-flight and prints a GO/NO-GO. Exit code is 0
// only when no check FAILED, so a provisioning script can gate on it.
func cmdDoctor(args []string) int {
	var o doctor.Options
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--check-caddy" {
			o.CheckCaddy = true
			continue
		}
		if a == "--pdns-key" || a == "--certmate-token" {
			fmt.Fprintf(os.Stderr, "flareover doctor: %s is no longer accepted (it exposes the secret on argv). Set PDNS_API_KEY / CERTMATE_TOKEN in the environment instead\n", a)
			return 2
		}
		if i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "flareover doctor: %s needs a value\n", a)
			return 2
		}
		i++
		switch a {
		case "--pdns-url":
			o.PDNSURL = args[i]
		case "--certmate-url":
			o.CertMateURL = args[i]
		case "--minio-endpoint":
			o.MinIOEndpoint = args[i]
		case "--spm-url":
			o.SPMURL = args[i]
		default:
			fmt.Fprintf(os.Stderr, "flareover doctor: unknown flag %q\n", a)
			return 2
		}
	}
	// Secrets come from the environment only, never argv.
	o.PDNSKey = os.Getenv("PDNS_API_KEY")
	o.CertMateToken = os.Getenv("CERTMATE_TOKEN")

	checks := doctor.Run(rootCtx, o)
	fmt.Print(render.Doctor(checks, render.Enabled(os.Stdout)))
	if len(checks) == 0 {
		return 2 // nothing to check → not a pass
	}
	if !doctor.GoNoGo(checks) {
		return 1
	}
	return 0
}

// cmdProviders prints the honest edge-node catalogue: EU-sovereign operators
// first, then EU-region hyperscalers with their jurisdiction exposure stated. It
// never blurs residency into sovereignty.
func cmdProviders(args []string) int {
	color := render.Enabled(os.Stdout)
	green, yellow, dim, reset := "", "", "", ""
	if color {
		green, yellow, dim, reset = "\033[32m", "\033[33m", "\033[2m", "\033[0m"
	}
	row := func(p provider.Provider) {
		fmt.Printf("  %-14s %-38s %s%s%s\n", p.Key, p.Name, dim, p.Residency, reset)
		fmt.Printf("  %-14s %s%s%s\n", "", dim, p.Exposure, reset)
	}
	fmt.Printf("%sEU-sovereign (EU-owned operator, EU jurisdiction only):%s\n", green, reset)
	for _, p := range provider.Sovereign() {
		row(p)
	}
	fmt.Printf("\n%sEU residency, US operator: pragmatic, but NOT sovereign (US CLOUD Act reach):%s\n", yellow, reset)
	for _, p := range provider.ResidencyOnly() {
		row(p)
	}
	fmt.Printf("\n%sUse a key with `flareover prepare --edge-provider <key>` to emit its edge cloud-init.%s\n", dim, reset)
	fmt.Printf("%sCorporate-jurisdiction info to inform a choice, not legal advice.%s\n", dim, reset)
	return 0
}

func loadDecisions(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parsing decisions %s: %w", path, err)
	}
	return m, nil
}

func loadSnapshot(path string) (cf.Snapshot, error) {
	var snap cf.Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return snap, fmt.Errorf("parsing snapshot %s: %w", path, err)
	}
	if err := snap.CheckSchemaVersion(); err != nil {
		return snap, fmt.Errorf("%s: %w", path, err)
	}
	if err := snap.Validate(); err != nil {
		return snap, fmt.Errorf("%s: %w", path, err)
	}
	return snap, nil
}

// splitCSV parses a comma-separated flag value into trimmed, non-empty parts.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

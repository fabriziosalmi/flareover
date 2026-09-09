// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package dnstarget is the single registry of authoritative-DNS backends.
//
// It exists because there used to be two. `prepare` resolved --dns in one
// switch and `provision` in another, each with its own hand-maintained list of
// aliases, its own error message, and no mechanism tying them together — so
// they drifted: `prepare --dns bunny` generated a zone that `provision --dns
// bunny` then rejected as unknown, mid-migration, with artifacts already on
// disk. Both verbs now resolve through Lookup, so a target either exists for
// the whole pipeline or does not exist at all.
//
// The second thing it buys is that per-provider credential loading lives beside
// the provider rather than inside the CLI. cmdProvision used to carry eight
// providers' worth of environment reading, presence checking and construction
// inline; that is what put it at cyclomatic complexity 131 and made every new
// backend an edit to the composition root.
package dnstarget

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
	"github.com/fabriziosalmi/flareover/internal/target/azuredns"
	"github.com/fabriziosalmi/flareover/internal/target/bunnydns"
	"github.com/fabriziosalmi/flareover/internal/target/clouddns"
	"github.com/fabriziosalmi/flareover/internal/target/gandidns"
	"github.com/fabriziosalmi/flareover/internal/target/hetznerdns"
	"github.com/fabriziosalmi/flareover/internal/target/leasewebdns"
	"github.com/fabriziosalmi/flareover/internal/target/ovhdns"
	"github.com/fabriziosalmi/flareover/internal/target/powerdns"
	"github.com/fabriziosalmi/flareover/internal/target/route53"
	"github.com/fabriziosalmi/flareover/internal/target/scalewaydns"
)

// Provisioner applies a zone to a live authoritative-DNS backend.
type Provisioner interface {
	Provision(ctx context.Context, z ir.DNSZone) error
}

// NameserverLister is implemented by backends that can report the delegation
// NS to publish at the registrar. Optional: not every API exposes them.
type NameserverLister interface {
	Nameservers(ctx context.Context, zone string) ([]string, error)
}

// DNSSECEnabler is implemented by backends that can turn DNSSEC on and return
// the DS records to publish. Only self-hosted PowerDNS can today; the managed
// providers require a console click, which is what Target.DNSSECNote says.
type DNSSECEnabler interface {
	EnableDNSSEC(ctx context.Context, zone string) ([]string, error)
}

// Opts carries the inputs a provisioner needs that are not environment
// variables. Credentials are never in here: they come from the environment
// only, so they cannot leak through argv.
type Opts struct {
	// PDNSURL is the self-hosted PowerDNS API root (--pdns-url).
	PDNSURL string
	// Nameservers are the delegation NS to record in the zone (--nameservers).
	Nameservers []string
}

// Target is one authoritative-DNS backend.
type Target struct {
	// Key is the canonical id, e.g. "scaleway".
	Key string
	// Aliases are the other accepted spellings, e.g. "scaleway-dns".
	Aliases []string
	// Label names the backend in progress output, including its honest
	// sovereignty framing.
	Label string
	// Sovereign is false for a US-operated provider, however EU its region.
	Sovereign bool
	// DNSSECNote is appended to the progress line when the zone wants DNSSEC
	// and this backend cannot enable it programmatically.
	DNSSECNote string
	// Generator renders the offline artifacts (`prepare`).
	Generator target.Generator
	// NewProvisioner builds the live applier (`provision`), or returns an error
	// naming the missing credentials. A nil field means the backend is
	// generate-only: it emits an apply script for the operator to run.
	NewProvisioner func(Opts) (Provisioner, error)
}

// GenerateOnly reports whether this target has no live applier.
func (t Target) GenerateOnly() bool { return t.NewProvisioner == nil }

// registry is the whole vocabulary, in the order `flareover` presents it:
// self-hosted first, then EU-owned managed, then the honestly-tiered
// US-operated ones.
var registry = []Target{
	{
		Key: "powerdns", Label: "PowerDNS (self-hosted)", Sovereign: true,
		Generator:      powerdns.Generator{},
		NewProvisioner: newPowerDNS,
	},
	{
		Key: "bunny", Aliases: []string{"bunny-dns", "bunnydns"},
		Label: "bunny.net DNS (EU-owned)", Sovereign: true,
		Generator: bunnydns.Generator{},
		// Generate-only: bunny.net's record API is not mapped, so prepare emits
		// an apply.sh the operator runs. Declaring it here rather than omitting
		// it is the point — `provision --dns bunny` now says what to do instead
		// of claiming the target does not exist.
		NewProvisioner: nil,
	},
	{
		Key: "scaleway", Aliases: []string{"scaleway-dns", "scalewaydns"},
		Label: "Scaleway", Sovereign: true,
		DNSSECNote: "enable it for the zone in the Scaleway console (not yet automated)",
		Generator:  scalewaydns.Generator{},
		NewProvisioner: envProvisioner(
			[]string{"SCW_SECRET_KEY", "SCW_DEFAULT_PROJECT_ID"},
			func(v map[string]string, _ Opts) Provisioner {
				p := scalewaydns.NewProvisioner(v["SCW_SECRET_KEY"], v["SCW_DEFAULT_PROJECT_ID"])
				overrideURL(&p.BaseURL, "SCW_API_URL")
				return p
			}),
	},
	{
		Key: "ovh", Aliases: []string{"ovh-dns", "ovhdns"},
		Label: "OVHcloud", Sovereign: true,
		DNSSECNote: "enable it in the OVH panel (not yet automated)",
		Generator:  ovhdns.Generator{},
		NewProvisioner: envProvisioner(
			[]string{"OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"},
			func(v map[string]string, _ Opts) Provisioner {
				p := ovhdns.NewProvisioner(v["OVH_APPLICATION_KEY"], v["OVH_APPLICATION_SECRET"], v["OVH_CONSUMER_KEY"])
				overrideURL(&p.BaseURL, "OVH_ENDPOINT")
				return p
			}),
	},
	{
		Key: "gandi", Aliases: []string{"gandi-dns", "gandidns"},
		Label: "Gandi LiveDNS", Sovereign: true,
		DNSSECNote: "manage it in the Gandi panel (not yet automated)",
		Generator:  gandidns.Generator{},
		NewProvisioner: envProvisioner([]string{"GANDI_PAT"},
			func(v map[string]string, _ Opts) Provisioner {
				p := gandidns.NewProvisioner(v["GANDI_PAT"])
				overrideURL(&p.BaseURL, "GANDI_ENDPOINT")
				return p
			}),
	},
	{
		Key: "leaseweb", Aliases: []string{"leaseweb-dns", "leasewebdns"},
		Label: "Leaseweb", Sovereign: true,
		DNSSECNote: "manage it in the Leaseweb panel (not yet automated)",
		Generator:  leasewebdns.Generator{},
		NewProvisioner: envProvisioner([]string{"LEASEWEB_API_KEY"},
			func(v map[string]string, _ Opts) Provisioner {
				p := leasewebdns.NewProvisioner(v["LEASEWEB_API_KEY"])
				overrideURL(&p.BaseURL, "LEASEWEB_ENDPOINT")
				return p
			}),
	},
	{
		Key: "hetzner", Aliases: []string{"hetzner-dns", "hetznerdns"},
		Label: "Hetzner · EU-owned, sovereign", Sovereign: true,
		DNSSECNote: "enable it in the Hetzner DNS console (no record-API to automate it)",
		Generator:  hetznerdns.Generator{},
		NewProvisioner: envProvisioner([]string{"HETZNER_DNS_TOKEN"},
			func(v map[string]string, _ Opts) Provisioner {
				p := hetznerdns.NewProvisioner(v["HETZNER_DNS_TOKEN"])
				overrideURL(&p.BaseURL, "HETZNER_DNS_ENDPOINT")
				return p
			}),
	},
	{
		Key: "route53", Aliases: []string{"aws", "aws-route53"},
		Label: "Route 53 · US-operated, not sovereign", Sovereign: false,
		DNSSECNote: "enable it in the Route 53 console (not yet automated)",
		Generator:  route53.Generator{},
		NewProvisioner: envProvisioner([]string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
			func(v map[string]string, _ Opts) Provisioner {
				// AWS_SESSION_TOKEN is optional (it is only set for STS creds),
				// so it is read directly rather than being required above.
				p := route53.NewProvisioner(v["AWS_ACCESS_KEY_ID"], v["AWS_SECRET_ACCESS_KEY"], os.Getenv("AWS_SESSION_TOKEN"))
				overrideURL(&p.Endpoint, "AWS_ENDPOINT_URL_ROUTE53")
				return p
			}),
	},
	{
		Key: "clouddns", Aliases: []string{"cloud-dns", "gcp", "google"},
		Label: "Cloud DNS · US-operated, not sovereign", Sovereign: false,
		DNSSECNote:     "enable it on the managed zone in the Cloud DNS console (not yet automated)",
		Generator:      clouddns.Generator{},
		NewProvisioner: newCloudDNS,
	},
	{
		Key: "azure", Aliases: []string{"azure-dns", "azuredns"},
		Label: "Azure DNS · US-operated, not sovereign", Sovereign: false,
		DNSSECNote: "enable it on the zone in the Azure portal (not yet automated)",
		Generator:  azuredns.Generator{},
		NewProvisioner: envProvisioner(
			[]string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP"},
			func(v map[string]string, _ Opts) Provisioner {
				p := azuredns.NewProvisioner(v["AZURE_TENANT_ID"], v["AZURE_CLIENT_ID"], v["AZURE_CLIENT_SECRET"],
					v["AZURE_SUBSCRIPTION_ID"], v["AZURE_RESOURCE_GROUP"])
				overrideURL(&p.BaseURL, "AZURE_ARM_ENDPOINT")
				overrideURL(&p.AuthHost, "AZURE_AUTH_HOST")
				return p
			}),
	},
}

// Lookup resolves a --dns value (canonical key or alias, case-insensitive).
// The empty string is PowerDNS, the default.
func Lookup(s string) (Target, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		s = "powerdns"
	}
	for _, t := range registry {
		if t.Key == s {
			return t, true
		}
		for _, a := range t.Aliases {
			if a == s {
				return t, true
			}
		}
	}
	return Target{}, false
}

// Keys returns the canonical keys, for a "want: …" error message. One list,
// used by every verb, so no two of them can advertise different vocabularies.
func Keys() []string {
	out := make([]string, 0, len(registry))
	for _, t := range registry {
		out = append(out, t.Key)
	}
	return out
}

// All returns every registered target, in presentation order.
func All() []Target { return append([]Target(nil), registry...) }

// UnknownError is the message both verbs print for an unrecognised --dns.
func UnknownError(verb, got string) error {
	return fmt.Errorf("flareover %s: unknown --dns %q (want: %s)", verb, got, strings.Join(Keys(), " | "))
}

// envProvisioner builds a NewProvisioner that requires a set of environment
// variables and reports precisely which ones are missing. This is the shape
// seven of the nine backends need, and collapsing it here is most of what
// removed the per-provider validation from the CLI.
func envProvisioner(required []string, build func(map[string]string, Opts) Provisioner) func(Opts) (Provisioner, error) {
	return func(o Opts) (Provisioner, error) {
		vals := make(map[string]string, len(required))
		var missing []string
		for _, k := range required {
			v := os.Getenv(k)
			if strings.TrimSpace(v) == "" {
				missing = append(missing, k)
			}
			vals[k] = v
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, fmt.Errorf("missing in the environment: %s", strings.Join(missing, ", "))
		}
		return build(vals, o), nil
	}
}

// overrideURL applies an endpoint override from the environment, if set.
func overrideURL(field *string, env string) {
	if u := strings.TrimSpace(os.Getenv(env)); u != "" {
		*field = u
	}
}

// pdnsAdapter fits PowerDNS to the Provisioner interface: its Provision takes
// the delegation nameservers as a third argument, and it is the only backend
// that can sign a zone rather than telling the operator to click a console.
type pdnsAdapter struct {
	p  *powerdns.Provisioner
	ns []string
}

func (a pdnsAdapter) Provision(ctx context.Context, z ir.DNSZone) error {
	return a.p.Provision(ctx, z, a.ns)
}

func (a pdnsAdapter) EnableDNSSEC(ctx context.Context, zone string) ([]string, error) {
	return a.p.EnableDNSSEC(ctx, zone)
}

func newPowerDNS(o Opts) (Provisioner, error) {
	if strings.TrimSpace(o.PDNSURL) == "" {
		return nil, fmt.Errorf("needs --pdns-url (and PDNS_API_KEY in the environment)")
	}
	key := os.Getenv("PDNS_API_KEY")
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("missing in the environment: PDNS_API_KEY")
	}
	return pdnsAdapter{p: powerdns.NewProvisioner(o.PDNSURL, key), ns: o.Nameservers}, nil
}

// newCloudDNS is separate because its credential is a file whose contents are
// read, so "missing" and "unreadable" are different failures.
func newCloudDNS(_ Opts) (Provisioner, error) {
	path := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if path == "" {
		return nil, fmt.Errorf("missing in the environment: GOOGLE_APPLICATION_CREDENTIALS (service-account key file)")
	}
	sa, err := os.ReadFile(path) // #nosec G304: an operator-supplied credential path, by design
	if err != nil {
		return nil, fmt.Errorf("read GOOGLE_APPLICATION_CREDENTIALS (%s): %w", path, err)
	}
	p, err := clouddns.NewProvisioner(sa, os.Getenv("GOOGLE_CLOUD_PROJECT"))
	if err != nil {
		return nil, err
	}
	overrideURL(&p.BaseURL, "CLOUDDNS_ENDPOINT")
	overrideURL(&p.TokenURI, "GOOGLE_TOKEN_URI")
	return p, nil
}

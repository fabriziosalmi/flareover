package validate

import "testing"

func TestZoneAcceptsValidZone(t *testing.T) {
	zone := `; flareover zone
$ORIGIN example.com.
$TTL 300
@	IN	SOA	ns1.example.com. hostmaster.example.com. (
		1
		3600
		600
		1209600
		300 )
@	IN	NS	ns1.example.com.
www	300	IN	A	203.0.113.10
api	300	IN	CNAME	www.example.com.
`
	ok, problems := Zone([]byte(zone))
	if !ok {
		t.Errorf("valid zone flagged: %v", problems)
	}
}

func TestZoneCatchesUnterminatedParen(t *testing.T) {
	// SOA opens '(' but never closes — a real structural break.
	zone := "@\tIN\tSOA\tns1. host. (\n\t\t1\n\t\t3600\n"
	ok, problems := Zone([]byte(zone))
	if ok || len(problems) == 0 {
		t.Fatal("unterminated SOA paren must be flagged")
	}
}

func TestZoneCatchesTruncatedRecord(t *testing.T) {
	zone := "$ORIGIN example.com.\nwww\n" // a bare owner with no type/rdata
	ok, problems := Zone([]byte(zone))
	if ok || len(problems) == 0 {
		t.Fatal("truncated record must be flagged")
	}
}

func TestZoneCatchesStrayCloseParen(t *testing.T) {
	zone := "www 300 IN A 203.0.113.10 )\n"
	ok, _ := Zone([]byte(zone))
	if ok {
		t.Fatal("stray ')' must be flagged")
	}
}

func TestCaddyfileNeverFalseFails(t *testing.T) {
	// Whether or not caddy is installed, a graceful result comes back: either a
	// skip (caddy absent) or a ran check — never a panic, never a silent pass.
	r := Caddyfile([]byte("example.com {\n\treverse_proxy 203.0.113.10:80\n}\n"))
	if r.Ran == "" && !r.Skipped() {
		t.Error("a no-run result must report Skipped()")
	}
	if r.Ran != "" && r.Detail == "" {
		t.Error("a check that ran should explain its outcome")
	}
}

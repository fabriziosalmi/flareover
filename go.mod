module github.com/fabriziosalmi/flareover

go 1.26

// Pinned, and bumped deliberately. The toolchain IS this project's dependency
// set — there are no modules — so the patch release that compiles a binary is
// the single input that decides most of its bytes, and leaving it to whatever
// setup-go served that day made two builds of the same tag differ with nothing
// recording which. 1.26.8 fixed the eighteen reachable standard-library
// advisories govulncheck reported against 1.26.0, and 1.26.9 the nine published
// after it (crypto/tls, mime/multipart, net/http; GO-2026-6608 to 6617). ci.yml
// runs govulncheck, so the next one will be a failing build rather than a
// discovery during an audit, which is how these nine surfaced.
toolchain go1.26.10

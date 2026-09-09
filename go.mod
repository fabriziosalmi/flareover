module github.com/fabriziosalmi/flareover

go 1.26

// Pinned, and bumped deliberately. The toolchain IS this project's dependency
// set — there are no modules — so the patch release that compiles a binary is
// the single input that decides most of its bytes, and leaving it to whatever
// setup-go served that day made two builds of the same tag differ with nothing
// recording which. 1.26.8 is also where the eighteen reachable standard-library
// advisories govulncheck reported against 1.26.0 are fixed; ci.yml runs
// govulncheck now, so the next one will be a failing build rather than a
// discovery during an audit.
toolchain go1.26.8

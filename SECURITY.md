# Security Policy

flareover generates and applies infrastructure configuration, so a defect can have real security
impact. Reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Instead, use one of:

- GitHub's private **"Report a vulnerability"** flow (Security tab → Advisories), or
- email **fabrizio.salmi@gmail.com** with the details.

Include, if you can: what you did, what happened, the impact, and a minimal reproduction. You will get
an acknowledgement as soon as reasonably possible, and credit in the fix unless you prefer to stay
anonymous.

## Scope

Especially interested in anything that would let flareover:

- emit behaviour-changing configuration that is **not** an AUTO or answered-ASK item (a break of the
  0% false-positive contract),
- leak a secret (a token, a private key, origin details) into a generated artifact or a log,
- weaken the target it stands up (e.g. an egress or WAF rule that fails open rather than closed).

## Supported versions

flareover is pre-1.0; fixes land on `main` and in the next tagged release. Please test against `main`
before reporting.

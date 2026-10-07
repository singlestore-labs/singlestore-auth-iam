# AGENTS.md

## Languages
Go, Python (`python/`), and Java (`java/`) are kept behavior-compatible. The
**Go implementation is authoritative** and is the only one with the verifier;
Python and Java are clients. Shared logic (verifier-side negotiation, defaults)
lives in Go; clients stay lean and defer to the server, with parity proven by
integration tests against the Go server rather than reimplemented + unit-tested.
When you change shared behavior or vocabulary, update all three.

Keep the implementations structurally aligned — same names, ordering, and
vocabulary, with parallel comments — so they can be audited by eye across
languages. Diverge only where justified (e.g. the verifier is Go-only).

## Compatibility
The wire protocol is additive: format tokens are stable forever, unknown tokens
are ignored, and the default on-the-wire behavior must not change. Make new
behavior opt-in.

## Dependencies
Prefer importing a well-maintained package over reimplementing (e.g. use the
cloud SDKs' ARN parsers). Reuse existing deps before adding new ones.

## Testing
- Use the `make` targets; don't run tools by hand in ways that bypass them.
- Run everything you can before pushing: `make format`, then `make test` and
  `make lint`.
- Cloud tests (`make on-remote-test*`) need credentials or a running Go test
  server; the tooling to invoke them may or may not be available — **check with
  the user**.
- Library (non-test) code must not reference `S2IAM_TEST_*` env vars; avoid the
  phrase "jwt token" (both enforced by `make test`).

## Security
This is an auth library: never log tokens, credentials, or signed assertions.

## Changelog
Update `CHANGELOG.md` for user-visible changes.

## Pull requests
When addressing review comments, reply as yourself (make clear it's the agent)
and resolve threads once handled.

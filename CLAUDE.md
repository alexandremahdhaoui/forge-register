# CLAUDE.md

forge-register keeps the catalog of adoptable package versions. It decides by
policy and never by hand.

Read ~/.claude/CLAUDE.md first. Those rules apply here.

## The two rules that shape everything

**The pipeline is the only writer, and consumers only consume tags.** Every
human input — admission, upgrade, opening a track — is a request record. The
CLI files requests and reads state; it never writes the index.

**A rejection must be correctable from its verdict alone.** Machine-readable
code, the requested version, alternatives with their severity vectors, and a
human message. A new failure mode is a new verdict code in
forge-register-spec plus a vector, never a free-form string.

## Policy is pure

`policycontroller` does no I/O. Severity vectors compare lexicographically
from critical down; unknown severity counts as high; a version that fixes a
high while adding a low still wins. Quarantine, the admission floor, the
track deny policies and the deprecation windows are all register-level
parameters — a consumer can read them and can never set them.

Engines are thin shells around controllers. If a decision cannot be written
as a table test, it does not belong in an engine.

## forge-register names no project

An ecosystem names a discovery adapter, so ecosystems are code. A package is
data that arrives in a request, never a word in this repo.
`hack/no-hardcoding.sh` fails the build on a known project name.

## The store is not ours

Records travel over forge-revision-spec's get/put/list transport, served by
forge-ci's ci-state-git with `spec.kinds: [index, request, verdict]`. Do not
build a state engine here; a DB store later is a new engine behind the same
transport. The conformance suite drives the register kinds plus the ten
transport vectors through the real engine.

## Traps inherited from forge-ci, still true here

- A `[]byte` field breaks over MCP. Payloads are strings.
- A nil map serializes to `null` and fails schema validation. Everything
  through `orEmpty`.
- Mockery needs `unroll-variadic: true`.
- A repo must gitignore its own build output or revisions never settle.
- `go test -run 'subtest'` matches the parent first. Use the full path.

## Build and test

```sh
forge build
forge test-all
```

Stages are lint, no-hardcoding, standalone, engine-docs, unwired,
architecture, docs, unit, conformance, e2e and coverage (90).

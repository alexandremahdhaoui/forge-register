# forge-register

The tool behind the register: the catalog of adoptable package versions a
workspace resolves against.

A **revision** (forge-ci) is proof that one tuple of commits worked. The
**register** is the catalog of versions a consumer may use, advanced only by
policy, written only by its own pipeline, tagged only on green. They meet in
one place: a green pipeline's release publishes a version into the register,
citing the revision that proved it.

## What is here

| Path | Holds |
|---|---|
| `cmd/register-discover` | Engine. Lists upstream versions per ecosystem and snapshots OSV. |
| `cmd/register-evaluate` | Engine. Runs the policy: upgrades, admissions, track opening, intake, deprecation. |
| `cmd/register-publish` | Engine. Admits internal packages by proof, with revision provenance. |
| `cmd/forge-register` | CLI. Files requests and reads state; never writes the index. |
| `internal/controller/policycontroller` | The whole algorithm, pure and table-tested. |

The document schemas live in forge-register-spec. The get/put/list transport
lives in forge-revision-spec and is served by forge-ci's `ci-state-git` with
`spec.kinds: [index, request, verdict]` — this repo ships no state engine.

## The algorithm, in one paragraph

Severity vector = counts of known unfixed vulns (critical, high, medium,
low), compared lexicographically from critical down. A candidate strictly
safer than current adopts immediately; an equal one adopts after quarantine
(freshness beats staleness); a worse one is held, with a verdict. Admission
picks the newest out-of-quarantine version passing the severity floor and
never substitutes silently — a rejection lists alternatives. Everything is
computed from a recorded OSV snapshot whose digest goes into the verdict, so
every decision replays and explains itself.

## Building it

```sh
forge test-all
```

Not `go test`. The gates have caught real breakage.

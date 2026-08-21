# Concepts

The register is the catalog of adoptable package versions. A revision
(forge-ci) is proof that one tuple of commits worked; the register is what a
consumer may use, advanced only by policy. They meet in one place: a green
pipeline's release publishes a version into the register, citing the revision
that proved it.

## Records

| Record | Is |
|---|---|
| track | A maintained line of one package, named by a semver prefix: `1` for a major, `1.27` for a maintained line. One current version per track; a version belongs to its longest matching prefix. One index file per track. |
| request | The only door into the register. Untrusted input; it moves the register only by passing policy, whoever files it. A request with no reason is a config error. |
| verdict | Every decision, written with its inputs. Answering a request is writing its verdict — the transport needs no delete. |
| advisory | The current version carries a vulnerability and no fix exists upstream. An advisory pierces every pin. |
| deprecation | Set by policy, never by hand: `no-fix` past its window, or `stale` past a successor. |

All three kinds travel over forge-revision-spec's get/put/list transport,
served by forge-ci's ci-state-git with `spec.kinds: [index, request, verdict]`.

## The severity vector

`(critical, high, medium, low)` — counts of known, unfixed vulnerabilities,
compared lexicographically from critical down. A critical never trades
against any number of lows; a version that fixes a high while adding a low
still wins. Unknown severity counts as high.

A register catalogs releases: a pre-release is never a candidate for
admission or upgrade, and only an exact request naming one admits it.

## Verdict codes

| Code | Means |
|---|---|
| adopted | The version entered the index. The track advanced. |
| up-to-date | Nothing newer in the track. Not upgrading is never silent. |
| held-worse-vector | The newer release is less safe than current. Staying. |
| held-quarantined | The candidate waits out its quarantine. |
| held-canary-red | The canary workspace went red; the adoption never published. |
| pending-admission | A passing version exists but is still in quarantine. |
| denied-over-floor | Every option carries a vulnerability at or above `admissionMaxSeverity`. Alternatives listed; living with one is an explicit re-request, never a default. |
| denied-quarantined | The exact version requested is still in quarantine. |
| denied-unknown-version | Upstream never released what was asked for. |
| denied-not-a-maintained-line | The prefix has had no release since a successor exists. A track is a fact about upstream; this is a pin, use a pin. |
| denied-security-regression | The track would open less safe than the default track's current. |
| denied-over-budget | The package already carries `maxTracksPerPackage` finer tracks. |

Every hold and denial carries a message and, where they exist, alternatives
the policy itself would accept — a rejection is correctable from its verdict
alone.

## Parameters

All policy knobs are register-level; a consumer can read them and can never
set them.

| Parameter | Governs |
|---|---|
| quarantineDays | How long a release bakes before an equal-safety adoption. Waived for a strictly safer version. |
| admissionMaxSeverity | The floor: nothing at or above it enters the index. |
| deprecateAfterDays | How long an advisory may stand unfixed before its track deprecates. |
| staleAfterDays | How long upstream may be silent, with a successor existing, before a track deprecates. |
| deprecatedGraceDays | How long a deprecated track resolves with a warning before it errors. |
| maxTracksPerPackage | The budget of finer tracks per package. |

## The two admission doors

External packages enter by **policy**: discovery, severity vector,
quarantine, canary. Internal packages enter by **proof**: `publish` records
the version with the revision id that proved it, minted by the pipeline that
released it.

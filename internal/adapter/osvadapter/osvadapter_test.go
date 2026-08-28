package osvadapter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

func fmtWarn(format string, args ...any) string { return fmt.Sprintf(format, args...) }

var toOSV = map[string]string{
	"go": "Go", "internal": "Go", "rust": "crates.io",
	"python": "PyPI", "typescript": "npm",
}

// The parser must read every field a decision rests on, out of the real
// bytes, for all 267 captured records. The expectations were written by a
// second implementation in another language and live in their own file.
func TestTheParserAgreesWithASecondReadingOfTheSameBytes(t *testing.T) {
	in, want := load(t)

	require.Len(t, in.Records, want.Counts.Records)
	require.Len(t, in.Packages, want.Counts.Packages)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	checked, unknown := 0, 0

	for _, m := range want.Match {
		osvEco := toOSV[m.Ecosystem]

		answers, _, err := q.Vulns(context.Background(), m.Ecosystem, m.Package, []string{m.Version})
		require.NoError(t, err)

		got := answers[m.Version]
		require.Equal(t, m.Outcome, string(got.Outcome),
			"%s %s@%s: outcome", m.Ecosystem, m.Package, m.Version)

		ids := make([]string, 0, len(got.Vulns))
		for _, v := range got.Vulns {
			ids = append(ids, v.ID)
		}

		require.ElementsMatch(t, m.IDs, ids,
			"%s %s@%s: the ranges decide, not the feed's filter", m.Ecosystem, m.Package, m.Version)

		for _, v := range got.Vulns {
			exp, ok := want.Parse[v.ID]
			require.True(t, ok, "%s has no stated expectation", v.ID)

			require.Equal(t, exp.Severity, string(v.Severity), "%s severity", v.ID)
			require.ElementsMatch(t, exp.Introduced, v.Introduced, "%s introduced", v.ID)
			require.ElementsMatch(t, exp.Fixed, v.FixedIn, "%s fixed", v.ID)
			require.ElementsMatch(t, exp.LastAffected, v.LastAffected, "%s last_affected", v.ID)
			require.ElementsMatch(t, exp.AffectedImports, v.AffectedImports, "%s imports", v.ID)
			require.NotEmpty(t, v.MatchedRange, "%s must say which range covered us", v.ID)

			checked++

			if exp.Severity == "" {
				unknown++
			}
		}

		_ = osvEco
	}

	require.Positive(t, checked, "the vectors must actually exercise a finding")
	t.Logf("checked %d findings across %d packages, %d with no published severity",
		checked, len(want.Match), unknown)
}

// The one finding the workspace actually has. It has no severity, no fix
// upstream ever, and an import scope that does not include anything we use -
// which is precisely why a gate that could not read those fields blocked a
// colleague on it with the words "no fix upstream" it had never checked.
func TestTheOneRealFindingReadsWhole(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	answers, digest, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.55.0"})
	require.NoError(t, err)

	got := answers["v0.55.0"]
	require.Equal(t, regtypes.OutcomeFindings, got.Outcome)
	require.True(t, got.Measured(), "a finding rests on something the feed actually said")
	require.Len(t, got.Vulns, 1)

	v := got.Vulns[0]
	require.Equal(t, "GO-2026-5932", v.ID)
	require.Empty(t, v.Severity, "the Go database publishes no severity for it, and inventing one is worse")
	require.Empty(t, v.FixedIn, "there is no fix and there never will be: the package is unmaintained by design")
	require.Contains(t, v.AffectedImports, "golang.org/x/crypto/openpgp")
	require.NotContains(t, v.AffectedImports, "golang.org/x/crypto/nacl/box",
		"nacl/box is what we import, and it is outside this advisory's scope")

	require.NotEqual(t, "sha256:e3b0c44298fc1c14", digest,
		"a measured answer must never digest to the sha256 of nothing")
}

// Three situations answer HTTP 200 with the body {}. They are different
// claims and the record has to keep them apart.
func TestAnEmptyAnswerIsNotACleanAnswer(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)

	var warnings []string

	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, format)
	}))

	// A package the feed has never heard of.
	answers, digest, err := q.Vulns(context.Background(), "go",
		"github.com/alexandremahdhaoui/does-not-exist", []string{"v1.0.0"})
	require.NoError(t, err)

	got := answers["v1.0.0"]
	require.Equal(t, regtypes.OutcomeNotFound, got.Outcome)
	require.False(t, got.Measured(), "an unmeasured package is an absence of knowledge, not a finding of safety")
	require.Contains(t, got.Reason, "carries no record")
	require.NotEmpty(t, warnings, "it has to be said out loud, not only filed")

	// A package that genuinely carries records, none of which reach the
	// version we are on. Taken from the stated expectations rather than
	// guessed, because guessing is what produced the fixtures this replaces.
	_, want := load(t)

	var eco, pkg, version string

	for _, m := range want.Match {
		if m.Outcome == "clean" {
			eco, pkg, version = m.Ecosystem, m.Package, m.Version

			break
		}
	}

	require.NotEmpty(t, pkg, "the vectors must contain a genuinely clean package")

	clean, cleanDigest, err := q.Vulns(context.Background(), eco, pkg, []string{version})
	require.NoError(t, err)
	require.Equal(t, regtypes.OutcomeClean, clean[version].Outcome)
	require.Contains(t, clean[version].Reason, "none of their ranges cover")

	require.NotEqual(t, digest, cleanDigest,
		"not-found and clean must not produce the same snapshot digest")
}

// An advisory that opens at "introduced: 0" and never names a fix covers
// every version there will ever be. Upgrading cannot clear it, which is why
// acknowledging it is the only way past - and why the gate has to read the
// range events instead of printing "no fix upstream" from a string constant.
func TestAnAdvisoryWithNoFixCoversEveryFutureVersion(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	for _, version := range []string{"v0.55.0", "v9.9.9", "v1000.0.0"} {
		answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{version})
		require.NoError(t, err)

		ids := make([]string, 0)
		for _, v := range answers[version].Vulns {
			ids = append(ids, v.ID)
		}

		require.Contains(t, ids, "GO-2026-5932",
			"%s: the openpgp advisory is unbounded, so no version escapes it", version)
	}
}

// A feed that is down measured nothing, and must say so rather than
// answering zero.
func TestAnUnreachableFeedIsNotACleanAnswer(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream is having a day", http.StatusServiceUnavailable)
	}))
	defer down.Close()

	var warnings []string

	q := osvadapter.New(nil, down.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, format)
	}))

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.55.0"})
	require.NoError(t, err, "a feed being down is not a programming fault")

	got := answers["v0.55.0"]
	require.Equal(t, regtypes.OutcomeUnreachable, got.Outcome)
	require.False(t, got.Measured(), "a feed that was down measured nothing")
	require.Contains(t, got.Reason, "could not be reached")
	require.Contains(t, got.Reason, "503")
	require.NotEmpty(t, warnings)
}

// Cross-validation. Our range walk and the feed's own filter must reach the
// same answer when the feed is right, and it usually is: asked about
// golang.org/x/crypto at v0.17.0 both say the same 36 records. This is the
// assertion that would catch a range walk that had quietly drifted.
func TestTheRangeWalkAgreesWithTheFeedWhenTheFeedIsRight(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)

	var warnings []string

	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, format)
	}))

	const version = "v0.17.0"

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{version})
	require.NoError(t, err)

	require.Len(t, answers[version].Vulns, len(in.Filtered["Go|golang.org/x/crypto|"+version].Vulns),
		"two independent readings of the same records must agree")
	require.Empty(t, warnings, "agreement is silent")
}

// A version that is not a version is refused rather than answered.
//
// Left alone it sorts below everything, so every advisory opening at
// "introduced: 0" appears to cover it. That is exactly the feed's own bug:
// asked about golang.org/x/crypto at "not-a-version" the API answers 200
// with 37 records when the truth is 36. Reproducing it locally would be
// worse than trusting the feed, because it would look like our own answer.
func TestAVersionThatIsNotAVersionIsRefused(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	_, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"not-a-version"})
	require.ErrorContains(t, err, "is not a version")

	// The captured proof that the feed does not refuse it.
	require.Len(t, in.Filtered["Go|golang.org/x/crypto|not-a-version"].Vulns, 37,
		"the API answered 37 for a string that is not a version")
	require.Len(t, in.Filtered["Go|golang.org/x/crypto|v0.17.0"].Vulns, 36,
		"and 36 for the real version, so its answer was wrong and looked right")
}

// When the two do disagree, the ranges win and the difference is said out
// loud. Silence here is how a wrong filter becomes a wrong verdict.
func TestADisagreementIsAlwaysReported(t *testing.T) {
	in, _ := load(t)

	// Serve a filter that drops a record the ranges do cover.
	in.Filtered["Go|golang.org/x/crypto|v0.30.0"] = in.Filtered["Go|golang.org/x/crypto|v0.55.0"]

	f := newFeed(t, in, 0)

	var warnings []string

	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, fmtWarn(format, args...))
	}))

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.30.0"})
	require.NoError(t, err)

	require.Greater(t, len(answers["v0.30.0"].Vulns), 1, "the ranges keep what the filter dropped")

	joined := strings.Join(warnings, "\n")
	require.Contains(t, joined, "the feed's own filter left it out - counting it")
	require.Contains(t, joined, "v0.30.0")
}

// The other direction, and the one that actually bit: the feed returns a
// record no published range supports. That is not hypothetical - asked about
// golang.org/x/crypto at "not-a-version" the API answers with 37 records when
// the truth is 36. The extra one must be dropped AND named.
func TestARecordTheRangesDoNotSupportIsDroppedAndNamed(t *testing.T) {
	in, _ := load(t)

	// The feed's filter claims every record it has for the package applies to
	// v0.55.0. Only one of them does.
	in.Filtered["Go|golang.org/x/crypto|v0.55.0"] = in.Filtered["Go|golang.org/x/crypto|"]

	f := newFeed(t, in, 0)

	var warnings []string

	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, fmtWarn(format, args...))
	}))

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.55.0"})
	require.NoError(t, err)

	require.Len(t, answers["v0.55.0"].Vulns, 1,
		"the ranges decide; the feed claiming 55 apply does not make them apply")

	joined := strings.Join(warnings, "\n")
	require.Contains(t, joined, "no published range covers this version - ignoring it")
	require.Contains(t, joined, "v0.55.0")
}

// Pagination is per result, not per response, and the loop has to terminate.
func TestPaginationFollowsEveryTokenAndStops(t *testing.T) {
	in, want := load(t)

	// Two records a page against a package carrying dozens forces many rounds.
	f := newFeed(t, in, 2)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	var expected []string

	for _, m := range want.Match {
		if m.Package == "golang.org/x/crypto" {
			expected = m.IDs
		}
	}

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.55.0"})
	require.NoError(t, err)

	ids := make([]string, 0)
	for _, v := range answers["v0.55.0"].Vulns {
		ids = append(ids, v.ID)
	}

	require.ElementsMatch(t, expected, ids,
		"a paged answer must be the same answer as an unpaged one")
	require.Greater(t, f.batches, 1, "the fixture must actually have paged")
}

// A record the feed took back is not an advisory any more.
func TestAWithdrawnRecordGatesNothing(t *testing.T) {
	in, _ := load(t)

	withdrawn := 0

	for id, raw := range in.Records {
		if strings.Contains(string(raw), `"withdrawn"`) {
			withdrawn++

			_ = id
		}
	}

	require.Positive(t, withdrawn, "the captured set must contain a withdrawn record to prove this")

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	_, want := load(t)

	for _, m := range want.Match {
		answers, _, err := q.Vulns(context.Background(), m.Ecosystem, m.Package, []string{m.Version})
		require.NoError(t, err)

		for _, v := range answers[m.Version].Vulns {
			require.False(t, want.Parse[v.ID].Withdrawn,
				"%s was withdrawn and must not gate %s", v.ID, m.Package)
		}
	}
}

// Every captured record, not only the one that happens to be a live finding.
//
// The finding-driven test above exercises exactly one record out of 267,
// which meant deleting the severity alias hop broke nothing and looked fine.
// A guard that covers one record covers nothing.
//
// Each probe names a record, its package, and a version that record's own
// published range covers. The pairing is explicit because a record commonly
// carries several maintenance branches and the answer differs per branch:
// tokio's ranges are 0.2.0-1.18.5, 1.19.0-1.20.4 and 1.21.0-1.24.2, so the
// fix a consumer needs depends entirely on which one they are inside.
func TestEveryCapturedRecordIsParsedWhole(t *testing.T) {
	in, want := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	require.Greater(t, len(want.Probes), 200, "the sweep must reach most of the captured set")

	checked, withSeverity := 0, 0

	for _, p := range want.Probes {
		answers, _, err := q.Vulns(context.Background(), p.Ecosystem, p.Package, []string{p.Version})
		require.NoError(t, err, "%s %s@%s", p.Ecosystem, p.Package, p.Version)

		var got *regtypes.Vuln

		for i := range answers[p.Version].Vulns {
			if answers[p.Version].Vulns[i].ID == p.ID {
				got = &answers[p.Version].Vulns[i]

				break
			}
		}

		require.NotNil(t, got, "%s must cover %s@%s, its own range says so",
			p.ID, p.Package, p.Version)

		exp := want.Parse[p.ID]

		require.Equal(t, exp.Severity, string(got.Severity),
			"%s severity: the database word, then the CVSS vector, then the aliases", p.ID)
		require.ElementsMatch(t, exp.Introduced, got.Introduced, "%s introduced", p.ID)
		require.ElementsMatch(t, exp.Fixed, got.FixedIn, "%s fixed", p.ID)
		require.ElementsMatch(t, exp.LastAffected, got.LastAffected, "%s last_affected", p.ID)
		require.ElementsMatch(t, exp.AffectedImports, got.AffectedImports, "%s imports", p.ID)
		require.NotEmpty(t, got.MatchedRange, "%s must name the range that covered us", p.ID)

		checked++

		if exp.Severity != "" {
			withSeverity++
		}
	}

	require.Greater(t, checked, 200)
	t.Logf("parsed %d records whole, %d resolved to a severity (%.1f%%)",
		checked, withSeverity, 100*float64(withSeverity)/float64(checked))
}

// last_affected closes a range without naming a fix, and must never be read
// as one. Only 12 of 267 captured records use it, none of them on a package
// the main sweep probes, so it gets its own vector or it is untested.
func TestLastAffectedClosesARangeWithoutNamingAFix(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	// GHSA-9crc-q9x8-hgqq covers vitest up to and including 0.0.125, with no
	// fixed event anywhere in the range.
	const id = "GHSA-9crc-q9x8-hgqq"

	inside, _, err := q.Vulns(context.Background(), "typescript", "vitest", []string{"0.0.125"})
	require.NoError(t, err)

	var found *regtypes.Vuln

	for i := range inside["0.0.125"].Vulns {
		if inside["0.0.125"].Vulns[i].ID == id {
			found = &inside["0.0.125"].Vulns[i]
		}
	}

	require.NotNil(t, found, "0.0.125 is the last affected version, so it is affected")
	require.Equal(t, []string{"0.0.125"}, found.LastAffected)
	require.Empty(t, found.FixedIn,
		"a version that ends a range is not a version that fixes anything")

	// One patch above the last affected version, the range is closed.
	outside, _, err := q.Vulns(context.Background(), "typescript", "vitest", []string{"0.0.126"})
	require.NoError(t, err)

	for _, v := range outside["0.0.126"].Vulns {
		require.NotEqual(t, id, v.ID, "last_affected 0.0.125 must not reach 0.0.126")
	}
}

// A record the feed took back is not an advisory any more.
//
// Named exactly rather than swept for: GHSA-jcgq-xh2f-2hfm was withdrawn and
// its range still reads "introduced 0, fixed 4.18.2", so any eslint below
// 4.18.2 would be gated by it if withdrawal were ignored. That is the whole
// failure mode, and a test that hunts for a case can miss it.
func TestAWithdrawnRecordNeverGates(t *testing.T) {
	in, want := load(t)

	const (
		id      = "GHSA-jcgq-xh2f-2hfm"
		pkg     = "eslint"
		version = "4.0.0"
	)

	require.True(t, want.Parse[id].Withdrawn, "the fixture must carry it as withdrawn")
	require.Contains(t, string(in.Records[id]), `"withdrawn"`)

	// Its range does cover the version, so only withdrawal can keep it out.
	require.Equal(t, []string{"4.18.2"}, want.Parse[id].Fixed)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	answers, _, err := q.Vulns(context.Background(), "typescript", pkg, []string{version})
	require.NoError(t, err)

	for _, v := range answers[version].Vulns {
		require.NotEqual(t, id, v.ID, "%s was withdrawn and must gate nothing", id)
		require.False(t, want.Parse[v.ID].Withdrawn, "%s was withdrawn too", v.ID)
	}
}

// What a package costs to read, and why each part of the cost exists.
//
// This measured 111 requests for one package at one version: 55 records, plus
// an alias hop for every one of them - including the 54 that covered no
// version we hold and were discarded immediately. Asking a second version of
// the same package cost 111 more.
//
// Two rules bring it down, and this pins both. A record is fetched once and
// remembered: it is immutable, so one fetch serves every version and every
// alias naming it. And the alias hop is asked only for a record that actually
// matched, because that is the only record whose severity anybody reads.
func TestReadingAPackageCostsOneFetchPerRecord(t *testing.T) {
	in, want := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	const pkg = "golang.org/x/crypto"

	named := len(in.Packages[osvKey("go", pkg)].Vulns)
	require.Greater(t, named, 20, "the fixture must carry a package worth measuring")

	_, _, err := q.Vulns(context.Background(), "go", pkg, []string{"v0.55.0"})
	require.NoError(t, err)

	first := f.fetches

	require.Equal(t, named, first,
		"one fetch per record the package named, and no alias hop for a record "+
			"that covered nothing")

	// A second version of the same package re-reads nothing.
	_, _, err = q.Vulns(context.Background(), "go", pkg, []string{"v0.17.0"})
	require.NoError(t, err)

	second := f.fetches - first

	require.Less(t, second, named,
		"the records are already known; only aliases of the newly matched "+
			"findings can still need fetching")

	t.Logf("%d records: %d fetches for the first version, %d more for the second",
		named, first, second)

	_ = want
}

// Why the CVSS step exists at all.
//
// Measured over the captured set it resolves nothing new: every record it
// answers is answered identically by the alias hop. What it does is answer
// locally. Reading a vector costs nothing; asking the aliases costs a fetch.
//
// So the proof is a budget. Only a record with no database word and no vector
// may reach for an alias. Delete the CVSS step and 26 records start chasing.
func TestTheCVSSStepPaysForItselfInFetches(t *testing.T) {
	in, want := load(t)

	f := newFeed(t, in, 0)
	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(string, ...any) {}))

	byPackage := map[string][]string{}
	for _, p := range want.Probes {
		key := p.Ecosystem + "|" + p.Package
		byPackage[key] = append(byPackage[key], p.Version)
	}

	named := map[string]bool{}
	bySource := map[string]int{}

	for key := range byPackage {
		eco, pkg, _ := strings.Cut(key, "|")

		for _, v := range in.Packages[osvKey(eco, pkg)].Vulns {
			named[v.ID] = true
		}

		_, _, err := q.Vulns(context.Background(), eco, pkg, byPackage[key][:1])
		require.NoError(t, err)
	}

	for id := range named {
		bySource[want.Parse[id].SeveritySource]++
	}

	require.Positive(t, bySource["cvss"], "the fixture must contain CVSS-answered records")
	require.Positive(t, bySource["alias"], "and alias-answered ones, or the budget is trivial")

	maxAliasHops := 0

	for id := range named {
		if want.Parse[id].SeveritySource == "alias" || want.Parse[id].SeveritySource == "" {
			var rec struct {
				Aliases []string `json:"aliases"`
			}

			_ = json.Unmarshal(in.Records[id], &rec)
			maxAliasHops += len(rec.Aliases)
		}
	}

	budget := len(named) + maxAliasHops

	require.LessOrEqual(t, f.fetches, budget,
		"%d fetches against a budget of %d (%d records, at most %d alias hops). "+
			"Records answered by a CVSS vector must not reach for their aliases.",
		f.fetches, budget, len(named), maxAliasHops)

	t.Logf("%d fetches, budget %d: %d records, %d answered by the database word, "+
		"%d by a CVSS vector, %d by an alias, %d with no severity anywhere",
		f.fetches, budget, len(named), bySource["word"], bySource["cvss"],
		bySource["alias"], bySource[""])
}

// One record failing to load is a feed condition, not a programming fault.
//
// It used to abort the entire run - and inside Process, after verdicts had
// already been written, leaving a half-answered request set. Rate limiting is
// the realistic trigger, so a single 429 was worse than a full outage, which
// merely warned.
func TestOneUnreadableRecordDoesNotAbortTheRun(t *testing.T) {
	in, _ := load(t)

	f := newFeed(t, in, 0)
	f.failRecord("GO-2026-5932", http.StatusTooManyRequests)

	var warnings []string

	q := osvadapter.New(nil, f.URL, osvadapter.WithWarner(func(format string, args ...any) {
		warnings = append(warnings, fmtWarn(format, args...))
	}))

	answers, _, err := q.Vulns(context.Background(), "go", "golang.org/x/crypto", []string{"v0.55.0"})
	require.NoError(t, err, "the feed refusing one record is not a programming fault")

	got := answers["v0.55.0"]
	require.Equal(t, regtypes.OutcomeUnreachable, got.Outcome,
		"nothing was measured, and that is what the record has to say")
	require.False(t, got.Measured())
	require.Contains(t, got.Reason, "429")
	require.NotEmpty(t, warnings)
}

func osvKey(ecosystem, pkg string) string {
	switch ecosystem {
	case "go", "internal":
		return "Go|" + pkg
	case "rust":
		return "crates.io|" + pkg
	case "python":
		return "PyPI|" + pkg
	case "typescript":
		return "npm|" + pkg
	}

	return pkg
}

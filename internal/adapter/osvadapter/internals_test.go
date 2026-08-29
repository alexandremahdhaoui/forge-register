package osvadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Small rules that no captured record happens to exercise, each of which
// could be deleted with every other test still green.

// A record covering the same package twice must count once. The vector it
// feeds is what the severity gate reads, so a double count promotes a finding
// into a class the feed never assigned it.
func TestARecordCoveringOnePackageTwiceCountsOnce(t *testing.T) {
	r := record{ID: "GHSA-twice", Affected: []affected{
		{Name: "p", Ecosystem: "Go", Ranges: []versionRange{{
			Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}},
		}}},
		{Name: "p", Ecosystem: "Go", Ranges: []versionRange{{
			Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "3.0.0"}},
		}}},
	}}

	got := (&HTTP{}).match(t.Context(), []record{r}, "Go", "p", "1.0.0")
	require.Len(t, got, 1)
	require.Equal(t, regtypes.Vector{High: 1}, regtypes.VectorOf(got))
}

// The feed can name the same id twice in one package answer. Reading it twice
// costs a fetch and double-counts the finding.
func TestARepeatedIDIsReadOnce(t *testing.T) {
	var all batchResult

	all.Vulns = append(all.Vulns,
		struct {
			ID string `json:"id"`
		}{ID: "GHSA-1"},
		struct {
			ID string `json:"id"`
		}{ID: "GHSA-1"})

	h := &HTTP{records: map[string]record{"GHSA-1": {ID: "GHSA-1"}}}

	got, err := h.recordsOf(t.Context(), all)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// Findings come back in a stable order. A verdict that reorders between runs
// is a diff nobody can read.
func TestFindingsAreOrdered(t *testing.T) {
	mk := func(id string) record {
		return record{ID: id, Affected: []affected{{
			Name: "p", Ecosystem: "Go",
			Ranges: []versionRange{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
		}}}
	}

	got := (&HTTP{}).match(t.Context(), []record{mk("GHSA-z"), mk("GHSA-a"), mk("GHSA-m")},
		"Go", "p", "1.0.0")

	require.Equal(t, []string{"GHSA-a", "GHSA-m", "GHSA-z"},
		[]string{got[0].ID, got[1].ID, got[2].ID})
}

// OSV writes distro ecosystems with a suffix: "Debian:11", "Alpine:v3.18".
// The part before the colon is the ecosystem, and an exact comparison drops
// every one of them.
func TestAnEcosystemSuffixIsNotPartOfTheEcosystem(t *testing.T) {
	require.Equal(t, "Debian", baseEcosystem("Debian:11"))
	require.Equal(t, "Alpine", baseEcosystem("Alpine:v3.18"))
	require.Equal(t, "Go", baseEcosystem("Go"))

	r := record{ID: "DEBIAN-1", Affected: []affected{{
		Name: "linux", Ecosystem: "Debian:11",
		Ranges: []versionRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}}}},
	}}}

	require.Len(t, (&HTTP{}).match(t.Context(), []record{r}, "Debian", "linux", "1.0"), 1)
}

// An import entry with no path is not an import scope. Carrying the empty
// string would read as a package everything imports.
func TestAnEmptyImportPathIsNotAScope(t *testing.T) {
	v := vulnOf(record{ID: "GO-1"}, affected{Imports: []string{"", "a/b", ""}}, "why")
	require.Equal(t, []string{"a/b"}, v.AffectedImports)
}

// The snapshot digest is what proves which answer a decision read, so it must
// not change with the order the feed happened to reply in.
func TestTheSnapshotDigestIsOrderIndependent(t *testing.T) {
	a := digestOf([]string{"1.0.0 queried", "1.0.0 GO-1 high"})
	b := digestOf([]string{"1.0.0 GO-1 high", "1.0.0 queried"})
	require.Equal(t, a, b)

	require.NotEqual(t, a, digestOf(nil))
	require.Equal(t, "sha256:e3b0c44298fc1c14", digestOf(nil),
		"an empty snapshot is the sha256 of nothing, which is why outcome is "+
			"stored beside it rather than inferred from it")
}

// CVSS v3, at the band edges and on the metrics most easily dropped.
func TestCVSSScoringMatchesTheSpecification(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   regtypes.Severity
		why    string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", regtypes.SeverityCritical, "9.8"},
		{
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", regtypes.SeverityCritical,
			"10.0: the scope multiplier is what takes it there",
		},
		{
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", regtypes.SeverityMedium,
			"6.4 under changed scope, where the privileges table differs",
		},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", regtypes.SeverityMedium, "5.4"},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", regtypes.SeverityLow, "1.8"},
		{
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", regtypes.SeverityLow,
			"no impact at all scores zero",
		},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", regtypes.SeverityHigh, "7.5"},
		// The other two band edges. Only 9.0 was pinned, so moving high to
		// 7.5 or medium to 4.5 changed nothing any test could see - and a
		// score landing exactly on a boundary is the one place a consumer
		// most needs the answer to be the published one.
		{
			"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", regtypes.SeverityHigh,
			"exactly 7.0, the low edge of high",
		},
		{
			"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N", regtypes.SeverityMedium,
			"exactly 4.0, the low edge of medium",
		},

		// The three below sit on a band edge and each isolates one rule.
		// Every one of them was scored a whole band low before, and no
		// vector in the captured set is close enough to notice.
		{
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", regtypes.SeverityCritical,
			"9.3 with the scope multiplier, 8.7 without it",
		},
		{
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L", regtypes.SeverityCritical,
			"9.1 with the changed-scope privileges table, 8.8 with the unchanged one",
		},
		{
			"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L", regtypes.SeverityCritical,
			"9.0 rounding up as CVSS requires, 8.9 rounding to nearest",
		},
	} {
		t.Run(tc.why, func(t *testing.T) {
			got, ok := severityOfVector("CVSS_V3", tc.vector)
			require.True(t, ok)
			require.Equal(t, tc.want, got)
		})
	}

	_, ok := severityOfVector("CVSS_V4",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	require.False(t, ok,
		"v4's base score is a lookup table, not a formula; inventing one is worse "+
			"than admitting we have none")

	_, ok = severityOfVector("CVSS_V3", "nonsense")
	require.False(t, ok)
}

// Every word a database publishes, including the one spelled two ways.
func TestEveryPublishedSeverityWordIsRead(t *testing.T) {
	for word, want := range map[string]regtypes.Severity{
		"CRITICAL": regtypes.SeverityCritical,
		"HIGH":     regtypes.SeverityHigh,
		"MODERATE": regtypes.SeverityMedium,
		"MEDIUM":   regtypes.SeverityMedium,
		"LOW":      regtypes.SeverityLow,
		"":         "",
		"unusual":  "",
	} {
		require.Equal(t, want, severityOfWord(word), "word %q", word)
	}
}

// Every record marked severitySource "cvss" in the expectations also carries
// a GHSA alias publishing the same word. So the alias fallback reproduced the
// expected answer on its own, and gutting the CVSS parser left both
// integration tests green - including the one that counts sources, because
// counting a source is not checking which one answered.
//
// Cut the aliases and the database_specific word out of those records and the
// vector is the only thing left that can answer.
func TestACVSSAnsweredRecordNeedsNoAlias(t *testing.T) {
	rawIn, err := os.ReadFile("../../../testdata/osv-records.json")
	require.NoError(t, err)

	var in struct {
		Records map[string]json.RawMessage `json:"records"`
	}

	require.NoError(t, json.Unmarshal(rawIn, &in))

	rawWant, err := os.ReadFile("../../../testdata/osv-expected.json")
	require.NoError(t, err)

	var want struct {
		Parse map[string]struct {
			Severity       string `json:"severity"`
			SeveritySource string `json:"severitySource"`
		} `json:"parse"`
	}

	require.NoError(t, json.Unmarshal(rawWant, &want))

	checked := 0

	for id, p := range want.Parse {
		if p.SeveritySource != "cvss" {
			continue
		}

		var doc map[string]any
		require.NoError(t, json.Unmarshal(in.Records[id], &doc))

		delete(doc, "aliases")
		delete(doc, "database_specific")

		stripped, err := json.Marshal(doc)
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(stripped)
		}))

		rec, err := New(nil, srv.URL).fetchRecord(context.Background(), id)
		srv.Close()
		require.NoError(t, err)

		require.Equal(t, p.Severity, string(rec.Severity),
			"%s has no alias and no database_specific word left, so its CVSS "+
				"vector is the only thing that can answer", id)

		checked++
	}

	require.Positive(t, checked, "the fixture must contain CVSS-answered records")
}

// Four lines nothing drove, each of which reads as a correct answer when it
// is wrong.
func TestTheFeedsOwnFailuresAreErrors(t *testing.T) {
	t.Run("a truncated batch is an error, not an empty answer", func(t *testing.T) {
		// Degrading to not-found here records "the feed carries no record
		// for this package" for a package the feed simply did not answer
		// about. That is the unmeasured-reads-as-examined bug again.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"results":[]}`)
		}))
		t.Cleanup(srv.Close)

		answers, _, err := New(nil, srv.URL).
			Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
		require.NoError(t, err)

		// Unreachable, never not-found: the feed did not say this package
		// has no records, it failed to answer. Recording that as not-found
		// puts an unmeasured package in the measured bucket.
		require.Equal(t, regtypes.OutcomeUnreachable, answers["v1.0.0"].Outcome)
		require.Contains(t, answers["v1.0.0"].Reason, "answered 0 of")
	})

	t.Run("a feed that never stops paging is an error, not a hang", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// The same token forever, which is what a broken feed does.
			_, _ = io.WriteString(w,
				`{"results":[{"vulns":[],"next_page_token":"always"},`+
					`{"vulns":[],"next_page_token":"always"}]}`)
		}))
		t.Cleanup(srv.Close)

		answers, _, err := New(nil, srv.URL).
			Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
		require.NoError(t, err)
		require.Equal(t, regtypes.OutcomeUnreachable, answers["v1.0.0"].Outcome)
		require.Contains(t, answers["v1.0.0"].Reason, "kept paging past")
	})
}

func TestACleanAnswerStillDigestsToSomething(t *testing.T) {
	// A package with no vulnerabilities and a feed nobody ever asked both
	// produce an empty snapshot, and sha256 of nothing is the same digest
	// either way. The per-version line is what tells them apart, and every
	// migrated record in the register carries that empty digest today - so
	// this is not hypothetical.
	// The feed knows the package and its one record does not cover this
	// version. That is measured-clean, and it is the answer that has to
	// digest to something.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w,
			`{"results":[{"vulns":[{"id":"X-1"}]},{"vulns":[]}]}`)
	})
	mux.HandleFunc("/v1/vulns/X-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"X-1","affected":[{`+
			`"package":{"name":"p","ecosystem":"Go"},`+
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}]}]}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	answers, snapshot, err := New(nil, srv.URL).
		Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
	require.NoError(t, err)
	require.Equal(t, regtypes.OutcomeClean, answers["v1.0.0"].Outcome)

	empty := sha256.Sum256(nil)
	require.NotEqual(t, "sha256:"+hex.EncodeToString(empty[:])[:16], snapshot,
		"a measured-clean package digests the same as one nobody asked about")
}

func TestEqualVersionsPutIntroducedFirst(t *testing.T) {
	// A range naming the same version as introduced and as fixed covers it:
	// the walk sets inside on introduced and clears it on fixed, so the
	// order of the two decides the answer. Sorting fixed first reports the
	// version clean.
	sorted := sortedEvents([]rangeEvent{{Fixed: "1.0.0"}, {Introduced: "1.0.0"}})
	require.Equal(t, "1.0.0", sorted[0].Introduced)
	require.Equal(t, "1.0.0", sorted[1].Fixed)
}

func TestNoImpactIsLowWhateverTheArithmeticSays(t *testing.T) {
	// All-none impact under changed scope rounds to 4.0, which is medium.
	// CVSS defines a zero-impact vector as 0.0, and the guard is what says
	// so; without it a vector that affects nothing reads as medium.
	got, ok := severityOfVector("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N")
	require.True(t, ok)
	require.Equal(t, regtypes.SeverityLow, got)
}

// OSV caps a querybatch at 1000 queries and answers 400 past it. The
// register sends one query per published version, so a package crosses the
// cap the moment it has published a thousand releases - and the packages
// that get there are the oldest, most depended upon and most attacked.
//
// Three tracks in a real workspace were silently unmeasured this way:
// typescript at 3809 versions, @types/node at 2358, typescript-eslint at
// 1549. Nothing blocked, because an unmeasured package warns rather than
// blocks, so the gate stopped covering exactly the packages it most needed
// to cover and the pipeline stayed green.
func TestABatchLargerThanTheFeedAcceptsIsSplit(t *testing.T) {
	const versions = 2500

	var sizes []int

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Queries []map[string]any `json:"queries"`
		}

		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))

		// The real endpoint's answer, verbatim.
		if len(in.Queries) > maxQueriesPerBatch {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":3,"message":"too many queries"}`)

			return
		}

		sizes = append(sizes, len(in.Queries))

		results := make([]map[string]any, len(in.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
		}

		out, _ := json.Marshal(map[string]any{"results": results})
		_, _ = w.Write(out)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	list := make([]string, versions)
	for i := range list {
		list[i] = fmt.Sprintf("1.0.%d", i)
	}

	answers, _, err := New(nil, srv.URL).Vulns(context.Background(), "typescript", "p", list)
	require.NoError(t, err)
	require.Len(t, answers, versions)

	// One query per version, plus the package-wide one.
	require.Equal(t, []int{1000, 1000, 501}, sizes,
		"the batch is chunked to the feed's own cap")

	// And every version got an answer, in its own right.
	for _, v := range list {
		require.Equal(t, regtypes.OutcomeNotFound, answers[v].Outcome,
			"%s was answered", v)
	}
}

// A 400 is the server answering, and answering clearly. Calling it
// unreachable sends the reader to check egress and firewalls; the two need
// opposite responses, wait and retry versus fix the caller.
func TestARefusalIsNotAnOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":3,"message":"too many queries"}`)
	}))
	t.Cleanup(srv.Close)

	answers, _, err := New(nil, srv.URL).
		Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
	require.NoError(t, err)

	got := answers["v1.0.0"]
	require.Equal(t, regtypes.OutcomeUnreachable, got.Outcome,
		"nothing was measured either way, so it still does not block")
	require.Contains(t, got.Reason, "refused the request",
		"a refusal reads differently from an outage")
	// The feed's own words, read out of the envelope rather than dumped
	// with it. Substituting ours turned a thirty second diagnosis into a
	// bisect against the live API.
	require.Contains(t, got.Reason, "too many queries")
	require.NotContains(t, got.Reason, `{"code"`,
		"the message is extracted, not the whole JSON body")
}

func TestAnOutageStillReadsAsAnOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream is down")
	}))
	t.Cleanup(srv.Close)

	answers, _, err := New(nil, srv.URL).
		Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
	require.NoError(t, err)
	require.Contains(t, answers["v1.0.0"].Reason, "could not be reached")
	require.Contains(t, answers["v1.0.0"].Reason, "upstream is down")
}

// TestARefusedRecordIsNotAnOutage covers the second endpoint.
//
// The batch endpoint got the refusal split and the record endpoint did not.
// It returned a bare status line that carried no refusal marker and no
// message from the feed, so a 4xx on a single record still read as "could
// not be read" - the same defect the batch fix removed, one function over.
func TestARefusedRecordIsNotAnOutage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"vulns":[{"id":"X-1"}]},{"vulns":[]}]}`)
	})
	mux.HandleFunc("/v1/vulns/X-1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":3,"message":"malformed id"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	answers, _, err := New(nil, srv.URL).
		Vulns(context.Background(), "go", "p", []string{"v1.0.0"})
	require.NoError(t, err)

	got := answers["v1.0.0"]
	require.Equal(t, regtypes.OutcomeUnreachable, got.Outcome,
		"nothing was measured either way, so it still does not block")
	require.Contains(t, got.Reason, "refused the request",
		"a refusal reads differently from an outage, whichever endpoint refused")
	require.Contains(t, got.Reason, "malformed id",
		"and it carries the feed's own words")
}

// TestEveryVersionGetsItsOwnAnswerAcrossChunks drives the arithmetic the
// chunking test above cannot see.
//
// That test asserts chunk sizes with a feed that answers the same empty
// record to every query, so all 2500 versions land on one identical answer
// and a stitch that scrambled the order would pass unchanged. Here the feed
// answers per version, so an answer landing on the wrong version fails.
//
// The boundary is deliberate: the vulnerable version sits at index 1000,
// the first slot of the second chunk, which is where an off-by-one in the
// merge would put someone else's answer.
func TestEveryVersionGetsItsOwnAnswerAcrossChunks(t *testing.T) {
	const (
		versions = 2500
		affected = 1000
	)

	list := make([]string, versions)
	for i := range list {
		list[i] = fmt.Sprintf("1.0.%d", i)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Queries []struct {
				Version string `json:"version"`
			} `json:"queries"`
		}

		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		require.LessOrEqual(t, len(in.Queries), maxQueriesPerBatch)

		results := make([]map[string]any, len(in.Queries))

		for i, q := range in.Queries {
			results[i] = map[string]any{"vulns": []any{}}

			// The package-wide query carries no version. It must name the
			// record or the walk never fetches it.
			if q.Version == "" || q.Version == list[affected] {
				results[i] = map[string]any{"vulns": []any{map[string]any{"id": "X-1"}}}
			}
		}

		out, _ := json.Marshal(map[string]any{"results": results})
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/v1/vulns/X-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"X-1","affected":[{`+
			`"package":{"name":"p","ecosystem":"Go"},`+
			`"versions":["`+list[affected]+`"]}]}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	answers, _, err := New(nil, srv.URL).Vulns(context.Background(), "go", "p", list)
	require.NoError(t, err)
	require.Len(t, answers, versions)

	for i, v := range list {
		want := regtypes.OutcomeClean
		if i == affected {
			want = regtypes.OutcomeFindings
		}

		require.Equalf(t, want, answers[v].Outcome,
			"%s (index %d) got the answer meant for another version", v, i)
	}
}

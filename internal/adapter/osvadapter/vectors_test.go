package osvadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// The vectors are captured from api.osv.dev and the expectations are stated
// by hand in a separate file. That separation is the point: the previous
// fixture was `{"database_specific":{"severity":"HIGH"}}`, shaped to match
// the parser rather than the API, so the parser was never shown a field it
// failed to read and `ecosystem_specific.imports` stayed invisible for a
// year. A fixture that derives its own expectations proves nothing, because
// one bug writes both sides.
type vectors struct {
	Records map[string]json.RawMessage `json:"records"`
	Queries map[string]struct {
		Vulns []json.RawMessage `json:"vulns"`
	} `json:"queries"`
}

type expectations struct {
	Expected map[string]struct {
		Severity        *string  `json:"severity"`
		Introduced      []string `json:"introduced"`
		Fixed           []string `json:"fixed"`
		FixExists       bool     `json:"fixExists"`
		AffectedImports []string `json:"affectedImports"`
		HasImportScope  bool     `json:"hasImportScope"`
	} `json:"expected"`
	ExpectedQueries map[string]struct {
		VulnIDs []string `json:"vulnIds"`
	} `json:"expectedQueries"`
}

func load(t *testing.T) (vectors, expectations) {
	t.Helper()

	var v vectors

	var e expectations

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "osv-records.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &v))

	raw, err = os.ReadFile(filepath.Join("..", "..", "..", "testdata", "osv-expected.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &e))

	return v, e
}

// feed serves the captured records the way OSV does, so the adapter is
// exercised over its real transport rather than through a seam.
func feed(t *testing.T, v vectors) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")

		record, ok := v.Records[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = w.Write(record)
	})

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Queries []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}

		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))

		results := make([]map[string]any, 0, len(in.Queries))

		for _, q := range in.Queries {
			key := q.Package.Name + "@" + q.Version
			vulns := []map[string]any{}

			if id, ok := strings.CutPrefix(q.Package.Name, "vectors/"); ok {
				vulns = append(vulns, map[string]any{"id": id})
				results = append(results, map[string]any{"vulns": vulns})

				continue
			}

			for _, raw := range v.Queries[key].Vulns {
				var vuln struct {
					ID string `json:"id"`
				}

				require.NoError(t, json.Unmarshal(raw, &vuln))

				vulns = append(vulns, map[string]any{"id": vuln.ID})
			}

			results = append(results, map[string]any{"vulns": vulns})
		}

		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"results": results}))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

func severityWord(s regtypes.Severity) string {
	switch s {
	case regtypes.SeverityCritical:
		return "CRITICAL"
	case regtypes.SeverityHigh:
		return "HIGH"
	case regtypes.SeverityMedium:
		return "MODERATE"
	case regtypes.SeverityLow:
		return "LOW"
	}

	return ""
}

// Every field osv-expected.json names must come back exactly. These are the
// fields that decide whether an advisory applies at all, and every one of
// them was discarded before this test existed.
func TestTheParserExtractsEveryDecidingField(t *testing.T) {
	t.Parallel()

	v, e := load(t)
	server := feed(t, v)

	// The query path is what fills a track, so drive the record parse
	// through it rather than reaching for an internal seam.
	for id, want := range e.Expected {
		t.Run(id, func(t *testing.T) {
			ecosystem, pkg, version := queryFor(t, id)

			byVersion, digest, err := osvadapter.New(server.Client(), server.URL).
				Vulns(context.Background(), ecosystem, pkg, []string{version})
			require.NoError(t, err)
			require.NotEmpty(t, digest)

			var got *regtypes.Vuln

			for i := range byVersion[version] {
				if byVersion[version][i].ID == id {
					got = &byVersion[version][i]
				}
			}

			require.NotNil(t, got, "the record must reach the caller")

			if want.Severity == nil {
				require.Empty(t, severityWord(got.Severity),
					"OSV published no severity: unknown must stay unknown, not be invented")
			} else {
				require.Equal(t, *want.Severity, severityWord(got.Severity))
			}

			require.ElementsMatch(t, want.Introduced, got.Introduced)
			require.ElementsMatch(t, want.Fixed, got.FixedIn)
			require.Equal(t, want.FixExists, len(got.FixedIn) > 0,
				"whether a fix exists is read from the record, never assumed")
			require.ElementsMatch(t, want.AffectedImports, got.AffectedImports)
			require.Equal(t, want.HasImportScope, len(got.AffectedImports) > 0,
				"no import scope is not the same claim as no imports affected")
		})
	}
}

// queryFor answers which query serves a record. Only x/crypto has a captured
// query; the rest are served under a synthetic package name so the record
// parse is still driven over the wire.
func queryFor(t *testing.T, id string) (ecosystem, pkg, version string) {
	t.Helper()

	switch id {
	case "GO-2026-5932":
		return "go", "golang.org/x/crypto", "0.55.0"
	case "RUSTSEC-2022-0040":
		return "rust", "vectors/" + id, "1.0.0"
	case "GHSA-29mw-wpgm-hmr9":
		return "typescript", "vectors/" + id, "1.0.0"
	case "GHSA-9wx4-h78v-vm56":
		return "python", "vectors/" + id, "1.0.0"
	}

	return "go", "vectors/" + id, "1.0.0"
}

// The stub feed returning nothing and a package genuinely carrying nothing
// are different claims. They digested identically before, which is why 492
// of 492 verdicts in golden-register assert zero vulnerabilities while
// citing the sha256 of an empty response.
func TestACleanAnswerIsNotAnUnmeasuredOne(t *testing.T) {
	t.Parallel()

	v, _ := load(t)
	server := feed(t, v)

	_, clean, err := osvadapter.New(server.Client(), server.URL).
		Vulns(context.Background(), "go", "github.com/spf13/cobra", []string{"1.10.2"})
	require.NoError(t, err)

	// An ecosystem the register does not query is the unmeasured case.
	_, unmeasured, err := osvadapter.New(server.Client(), server.URL).
		Vulns(context.Background(), "elvish", "whatever", []string{"1.0.0"})
	require.NoError(t, err)

	require.NotEqual(t, unmeasured, clean,
		"a measured-clean package must not digest like a feed nobody asked")
	require.Equal(t, "sha256:e3b0c44298fc1c14", unmeasured,
		"the unmeasured digest stays recognisable: it is the sha256 of nothing")
}

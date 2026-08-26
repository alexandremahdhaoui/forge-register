package osvadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

func fakeOSV(t *testing.T) string {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[
			{"vulns":[{"id":"CVE-1"},{"id":"CVE-2"}]},
			{}
		]}`))
	})
	mux.HandleFunc("/v1/vulns/CVE-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"database_specific":{"severity":"HIGH"}}`))
	})
	mux.HandleFunc("/v1/vulns/CVE-2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"severity":[{"type":"CVSS_V3","score":"..."}]}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL
}

func TestVulnsClassifyBySeverityAndDigestTheSnapshot(t *testing.T) {
	q := osvadapter.New(nil, fakeOSV(t))

	byVersion, digest, err := q.Vulns(context.Background(), "rust", "example-crate",
		[]string{"1.0.0", "1.0.1"})
	require.NoError(t, err)

	require.Len(t, byVersion["1.0.0"], 2)
	require.Empty(t, byVersion["1.0.1"])

	vector := regtypes.VectorOf(byVersion["1.0.0"])
	// CVE-1 is HIGH; CVE-2's severity could not be classified, which counts
	// as high, the safe default.
	require.Equal(t, regtypes.Vector{High: 2}, vector)

	require.Contains(t, digest, "sha256:")

	// The digest is stable across calls: the snapshot is canonicalised.
	_, again, err := q.Vulns(context.Background(), "rust", "example-crate",
		[]string{"1.0.0", "1.0.1"})
	require.NoError(t, err)
	require.Equal(t, digest, again)
}

func TestAnEcosystemWithoutAFeedAnswersEmpty(t *testing.T) {
	q := osvadapter.New(nil, fakeOSV(t))

	byVersion, digest, err := q.Vulns(context.Background(), "papyrus", "scrolls",
		[]string{"0.3.0"})
	require.NoError(t, err)
	require.Empty(t, byVersion)
	require.NotEmpty(t, digest)
}

// Internal packages enter by proof, but they are public Go modules and
// their vulnerabilities are as real as anyone's: the feed is asked under
// OSV's Go ecosystem.
func TestInternalPackagesAskTheGoFeed(t *testing.T) {
	var asked string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Queries []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
			} `json:"queries"`
		}

		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		require.NotEmpty(t, in.Queries)
		asked = in.Queries[0].Package.Ecosystem

		_, _ = w.Write([]byte(`{"results":[{}]}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	q := osvadapter.New(nil, server.URL)

	_, _, err := q.Vulns(context.Background(), "internal",
		"github.com/example/toolchain-member", []string{"v0.1.0-dev.r00000001.gaaa"})
	require.NoError(t, err)
	require.Equal(t, "Go", asked)
}

func TestAShortBatchAnswerIsAnError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	_, _, err := osvadapter.New(nil, server.URL).Vulns(context.Background(), "go", "example.com/pkg",
		[]string{"v1.0.0"})
	require.ErrorContains(t, err, "1 versions")
}

func TestEverySeverityClassMaps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[
			{"id":"C"},{"id":"H"},{"id":"M"},{"id":"L"}
		]}]}`))
	})

	for id, severity := range map[string]string{
		"C": "CRITICAL", "H": "HIGH", "M": "MODERATE", "L": "LOW",
	} {
		id, severity := id, severity
		mux.HandleFunc("/v1/vulns/"+id, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"database_specific":{"severity":"` + severity + `"}}`))
		})
	}

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	byVersion, _, err := osvadapter.New(nil, server.URL).Vulns(context.Background(),
		"rust", "x", []string{"1.0.0"})
	require.NoError(t, err)
	require.Equal(t, regtypes.Vector{Critical: 1, High: 1, Medium: 1, Low: 1},
		regtypes.VectorOf(byVersion["1.0.0"]))
}

func TestAFailingFeedIsAnError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"X"}]}]}`))
	})
	mux.HandleFunc("/v1/vulns/X", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	_, _, err := osvadapter.New(nil, server.URL).Vulns(context.Background(),
		"rust", "x", []string{"1.0.0"})
	require.ErrorContains(t, err, "status 500")
}

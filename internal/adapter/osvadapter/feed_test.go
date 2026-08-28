package osvadapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// captured is osv-records.json: real response bodies, nothing hand written.
type captured struct {
	Packages map[string]struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"packages"`
	Records  map[string]json.RawMessage `json:"records"`
	Filtered map[string]struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"filtered"`
}

// expectations is osv-expected.json: stated by hand, in a separate file.
type expectations struct {
	Parse map[string]struct {
		Severity        string   `json:"severity"`
		Introduced      []string `json:"introduced"`
		Fixed           []string `json:"fixed"`
		LastAffected    []string `json:"lastAffected"`
		AffectedImports []string `json:"affectedImports"`
		Withdrawn       bool     `json:"withdrawn"`
		SeveritySource  string   `json:"severitySource"`
	} `json:"parse"`
	Match []struct {
		Ecosystem string   `json:"ecosystem"`
		Package   string   `json:"package"`
		Version   string   `json:"version"`
		Records   int      `json:"records"`
		IDs       []string `json:"ids"`
		Outcome   string   `json:"outcome"`
	} `json:"match"`
	Probes []struct {
		ID        string `json:"id"`
		Ecosystem string `json:"ecosystem"`
		Package   string `json:"package"`
		Version   string `json:"version"`
	} `json:"probes"`
	Counts struct {
		Records          int `json:"records"`
		Packages         int `json:"packages"`
		SeverityResolved int `json:"severityResolved"`
		SeverityUnknown  int `json:"severityUnknown"`
	} `json:"counts"`
}

func load(t *testing.T) (captured, expectations) {
	t.Helper()

	var in captured

	var want expectations

	raw, err := os.ReadFile("../../../testdata/osv-records.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &in))

	raw, err = os.ReadFile("../../../testdata/osv-expected.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &want))

	return in, want
}

// feed replays the captured responses over real HTTP, so the wire types are
// exercised rather than assumed. It also counts requests, which is how the
// pagination and batching claims are checked rather than asserted.
type feed struct {
	*httptest.Server

	mu       sync.Mutex
	batches  int
	fetches  int
	pageSize int
	failing  map[string]int
}

// failRecord makes one id answer with a status instead of a body, which is
// what rate limiting looks like from here.
func (f *feed) failRecord(id string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failing == nil {
		f.failing = map[string]int{}
	}

	f.failing[id] = status
}

func newFeed(t *testing.T, in captured, pageSize int) *feed {
	t.Helper()

	f := &feed{pageSize: pageSize}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.Header.Get("User-Agent"), "forge-register",
			"crates.io answers 403 without a User-Agent; every feed gets one")

		f.mu.Lock()
		f.batches++
		f.mu.Unlock()

		var req struct {
			Queries []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Version   string `json:"version"`
				PageToken string `json:"page_token"`
			} `json:"queries"`
		}

		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		type vuln struct {
			ID string `json:"id"`
		}

		type result struct {
			Vulns         []vuln `json:"vulns"`
			NextPageToken string `json:"next_page_token,omitempty"`
		}

		out := struct {
			Results []result `json:"results"`
		}{}

		for _, q := range req.Queries {
			key := q.Package.Ecosystem + "|" + q.Package.Name

			var ids []string

			if q.Version == "" {
				for _, v := range in.Packages[key].Vulns {
					ids = append(ids, v.ID)
				}
			} else if got, ok := in.Filtered[key+"|"+q.Version]; ok {
				for _, v := range got.Vulns {
					ids = append(ids, v.ID)
				}
			}

			// Page exactly the way the real feed does: a token per result,
			// carrying an offset, cleared on the last page.
			from := 0
			if q.PageToken != "" {
				_, _ = fmtSscan(q.PageToken, &from)
			}

			res := result{Vulns: []vuln{}}

			end := len(ids)
			if f.pageSize > 0 && from+f.pageSize < end {
				end = from + f.pageSize
				res.NextPageToken = fmtSprint(end)
			}

			for _, id := range ids[min(from, len(ids)):end] {
				res.Vulns = append(res.Vulns, vuln{ID: id})
			}

			out.Results = append(out.Results, res)
		}

		require.NoError(t, json.NewEncoder(w).Encode(out))
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, r.Header.Get("User-Agent"), "forge-register")

		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")

		f.mu.Lock()
		f.fetches++
		f.mu.Unlock()

		f.mu.Lock()
		status := f.failing[id]
		f.mu.Unlock()

		if status != 0 {
			http.Error(w, `{"code":8,"message":"rate limited"}`, status)

			return
		}

		body, ok := in.Records[id]
		if !ok {
			http.Error(w, `{"code":5,"message":"Vulnerability not found"}`, http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	return f
}

func fmtSscan(s string, n *int) (int, error) {
	v := 0

	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}

		v = v*10 + int(c-'0')
	}

	*n = v

	return 1, nil
}

func fmtSprint(n int) string {
	if n == 0 {
		return "0"
	}

	var b []byte

	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}

	return string(b)
}

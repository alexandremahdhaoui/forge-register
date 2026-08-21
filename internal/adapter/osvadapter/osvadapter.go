// Package osvadapter reads known vulnerabilities from an OSV-shaped feed and
// records the snapshot digest every verdict cites, so a decision replays and
// explains itself.
package osvadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Querier reads the vulnerabilities affecting each of a package's versions.
type Querier interface {
	Vulns(ctx context.Context, ecosystem, pkg string, versions []string) (map[string][]regtypes.Vuln, string, error)
}

// ecosystems maps register ecosystems to OSV's names. Internal packages have
// no feed: their admission path is proof, not policy.
var ecosystems = map[string]string{
	"go":         "Go",
	"rust":       "crates.io",
	"python":     "PyPI",
	"typescript": "npm",
}

// HTTP implements Querier over OSV's querybatch and vuln endpoints.
type HTTP struct {
	client *http.Client
	base   string
}

var _ Querier = (*HTTP)(nil)

func New(client *http.Client, base string) *HTTP {
	if client == nil {
		client = http.DefaultClient
	}

	if base == "" {
		base = "https://api.osv.dev"
	}

	return &HTTP{client: client, base: base}
}

// Vulns queries every version in one batch, resolves each vulnerability's
// severity once, and returns the sha256 digest of the canonical response set.
func (h *HTTP) Vulns(ctx context.Context, ecosystem, pkg string, versions []string) (map[string][]regtypes.Vuln, string, error) {
	osvEco, ok := ecosystems[ecosystem]
	if !ok {
		return map[string][]regtypes.Vuln{}, digestOf(nil), nil
	}

	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}

	var in struct {
		Queries []query `json:"queries"`
	}

	for _, v := range versions {
		q := query{Version: v}
		q.Package.Name = pkg
		q.Package.Ecosystem = osvEco
		in.Queries = append(in.Queries, q)
	}

	var out struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}

	if err := h.postJSON(ctx, h.base+"/v1/querybatch", in, &out); err != nil {
		return nil, "", fmt.Errorf("querying vulnerabilities for %s: %w", pkg, err)
	}

	if len(out.Results) != len(versions) {
		return nil, "", fmt.Errorf("querying vulnerabilities for %s: %d results for %d versions",
			pkg, len(out.Results), len(versions))
	}

	severities := map[string]regtypes.Severity{}
	byVersion := make(map[string][]regtypes.Vuln, len(versions))
	snapshot := make([]string, 0, len(versions))

	for i, version := range versions {
		var vulns []regtypes.Vuln

		for _, v := range out.Results[i].Vulns {
			severity, ok := severities[v.ID]
			if !ok {
				var err error

				severity, err = h.severityOf(ctx, v.ID)
				if err != nil {
					return nil, "", err
				}

				severities[v.ID] = severity
			}

			vulns = append(vulns, regtypes.Vuln{ID: v.ID, Severity: severity})
			snapshot = append(snapshot, version+" "+v.ID+" "+string(severity))
		}

		byVersion[version] = vulns
	}

	return byVersion, digestOf(snapshot), nil
}

// severityOf resolves one vulnerability's severity. Anything the feed cannot
// classify counts as high downstream, so unknown maps to an empty severity.
func (h *HTTP) severityOf(ctx context.Context, id string) (regtypes.Severity, error) {
	var body struct {
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+"/v1/vulns/"+id, nil)
	if err != nil {
		return "", fmt.Errorf("building request for %s: %w", id, err)
	}

	res, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("reading vulnerability %s: %w", id, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("reading vulnerability %s: status %d", id, res.StatusCode)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("reading vulnerability %s: %w", id, err)
	}

	if err := json.Unmarshal(raw, &body); err != nil {
		return "", fmt.Errorf("decoding vulnerability %s: %w", id, err)
	}

	switch body.DatabaseSpecific.Severity {
	case "CRITICAL":
		return regtypes.SeverityCritical, nil
	case "HIGH":
		return regtypes.SeverityHigh, nil
	case "MODERATE", "MEDIUM":
		return regtypes.SeverityMedium, nil
	case "LOW":
		return regtypes.SeverityLow, nil
	}

	return "", nil
}

func (h *HTTP) postJSON(ctx context.Context, u string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encoding request for %s: %w", u, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request for %s: %w", u, err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting %s: %w", u, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("posting %s: status %d", u, res.StatusCode)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading %s: %w", u, err)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s: %w", u, err)
	}

	return nil
}

// digestOf canonicalises the snapshot lines so the digest is stable whatever
// order the feed answered in.
func digestOf(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)

	sum := sha256.Sum256([]byte(joinLines(sorted)))

	return "sha256:" + hex.EncodeToString(sum[:8])
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}

	return out
}

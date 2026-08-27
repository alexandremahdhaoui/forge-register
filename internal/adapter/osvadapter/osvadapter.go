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
	"strings"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Querier reads the vulnerabilities affecting each of a package's versions.
type Querier interface {
	Vulns(ctx context.Context, ecosystem, pkg string, versions []string) (map[string][]regtypes.Vuln, string, error)
}

// ecosystems maps register ecosystems to OSV's names. Internal packages
// enter by proof, not discovery - but they are public Go modules and their
// vulnerabilities are as real as anyone's, so their vectors are asked
// under OSV's Go ecosystem.
var ecosystems = map[string]string{
	"go":         "Go",
	"internal":   "Go",
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

	known := map[string]details{}
	byVersion := make(map[string][]regtypes.Vuln, len(versions))
	snapshot := make([]string, 0, len(versions))

	for i, version := range versions {
		var vulns []regtypes.Vuln

		// Every version answered gets a snapshot line, even a clean one.
		// Without it a package with no vulnerabilities digests to the
		// sha256 of nothing - which is also what a feed that was never
		// asked digests to, so "clean" and "unmeasured" became the same
		// record. They are not the same claim.
		snapshot = append(snapshot, version+" queried")

		for _, v := range out.Results[i].Vulns {
			d, ok := known[v.ID]
			if !ok {
				var err error

				d, err = h.detailsOf(ctx, v.ID)
				if err != nil {
					return nil, "", err
				}

				known[v.ID] = d
			}

			// A withdrawn record is one the feed took back. It is not an
			// advisory any more and must not gate anything.
			if d.withdrawn {
				continue
			}

			vulns = append(vulns, regtypes.Vuln{
				ID:              v.ID,
				Severity:        d.severity,
				Introduced:      d.introduced,
				FixedIn:         d.fixed,
				AffectedImports: d.imports,
			})

			snapshot = append(snapshot, version+" "+v.ID+" "+string(d.severity)+
				" fixed="+strings.Join(d.fixed, ",")+
				" imports="+strings.Join(d.imports, ","))
		}

		byVersion[version] = vulns
	}

	return byVersion, digestOf(snapshot), nil
}

// details is everything a consumer needs from one OSV record. The feed
// answers a question about a package; whether a given consumer is affected
// is a different question, answered later against that consumer's own
// imports, so this reads facts and decides nothing.
type details struct {
	severity   regtypes.Severity
	introduced []string
	fixed      []string
	imports    []string
	withdrawn  bool
}

// detailsOf reads one vulnerability record whole. Everything here was
// discarded before: the range events that say whether a fix exists, and the
// import paths that say what the advisory actually covers. Events are
// unioned across every affected block, because a record commonly splits one
// vulnerability across branches (a stdlib line and a module line, say) and
// the fix a consumer needs may live in any of them.
func (h *HTTP) detailsOf(ctx context.Context, id string) (details, error) {
	var body struct {
		Withdrawn        string `json:"withdrawn"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Affected []struct {
			Ranges []struct {
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
				} `json:"events"`
			} `json:"ranges"`
			EcosystemSpecific struct {
				Imports []struct {
					Path string `json:"path"`
				} `json:"imports"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}

	raw, err := h.getJSON(ctx, h.base+"/v1/vulns/"+id, id, &body)
	if err != nil {
		return details{}, err
	}

	_ = raw

	out := details{severity: severityFrom(body.DatabaseSpecific.Severity), withdrawn: body.Withdrawn != ""}

	introduced := map[string]bool{}
	fixed := map[string]bool{}
	paths := map[string]bool{}

	for _, affected := range body.Affected {
		for _, r := range affected.Ranges {
			for _, e := range r.Events {
				if e.Introduced != "" {
					introduced[e.Introduced] = true
				}

				// last_affected closes a range without naming a fix, so it
				// is deliberately not folded in here: a version that ends
				// the affected range is not a version that fixes anything.
				if e.Fixed != "" {
					fixed[e.Fixed] = true
				}
			}
		}

		for _, imp := range affected.EcosystemSpecific.Imports {
			if imp.Path != "" {
				paths[imp.Path] = true
			}
		}
	}

	out.introduced = sortedKeys(introduced)
	out.fixed = sortedKeys(fixed)
	out.imports = sortedKeys(paths)

	return out, nil
}

// severityFrom maps OSV's word to ours. A word the feed does not publish
// stays empty, and empty counts as high downstream - conservative by
// decision, and the emptiness is preserved rather than invented so a
// consumer can tell "unknown" from "low".
func severityFrom(word string) regtypes.Severity {
	switch word {
	case "CRITICAL":
		return regtypes.SeverityCritical
	case "HIGH":
		return regtypes.SeverityHigh
	case "MODERATE", "MEDIUM":
		return regtypes.SeverityMedium
	case "LOW":
		return regtypes.SeverityLow
	}

	return ""
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

func (h *HTTP) getJSON(ctx context.Context, u, what string, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", what, err)
	}

	res, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading vulnerability %s: %w", what, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading vulnerability %s: status %d", what, res.StatusCode)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading vulnerability %s: %w", what, err)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("decoding vulnerability %s: %w", what, err)
	}

	return raw, nil
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

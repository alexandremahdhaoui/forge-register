// Package registryadapter lists a package's released versions per ecosystem.
// An ecosystem names an upstream registry and nothing else: what comes back
// is versions and release dates, never an opinion.
package registryadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// ErrEcosystem names an ecosystem no adapter serves.
var ErrEcosystem = errors.New("unknown ecosystem")

// Lister lists upstream releases of one package.
type Lister interface {
	Versions(ctx context.Context, ecosystem, pkg string) ([]regtypes.Candidate, error)
}

// BaseURLs overrides the upstream registries, for tests and mirrors. A zero
// value uses the public registries.
type BaseURLs struct {
	GoProxy string
	Crates  string
	PyPI    string
	NPM     string
}

func (b BaseURLs) orDefaults() BaseURLs {
	if b.GoProxy == "" {
		b.GoProxy = "https://proxy.golang.org"
	}

	if b.Crates == "" {
		b.Crates = "https://crates.io"
	}

	if b.PyPI == "" {
		b.PyPI = "https://pypi.org"
	}

	if b.NPM == "" {
		b.NPM = "https://registry.npmjs.org"
	}

	return b
}

// HTTP implements Lister over the registries' public JSON endpoints.
type HTTP struct {
	client *http.Client
	base   BaseURLs
}

var _ Lister = (*HTTP)(nil)

func New(client *http.Client, base BaseURLs) *HTTP {
	if client == nil {
		client = http.DefaultClient
	}

	return &HTTP{client: client, base: base.orDefaults()}
}

func (h *HTTP) Versions(ctx context.Context, ecosystem, pkg string) ([]regtypes.Candidate, error) {
	switch ecosystem {
	case "go":
		return h.goVersions(ctx, pkg)
	case "rust":
		return h.crateVersions(ctx, pkg)
	case "python":
		return h.pypiVersions(ctx, pkg)
	case "typescript":
		return h.npmVersions(ctx, pkg)
	}

	return nil, fmt.Errorf("listing %s: %w", ecosystem, ErrEcosystem)
}

// goVersions reads the module proxy: @v/list for the versions, @v/<v>.info for
// each release time.
func (h *HTTP) goVersions(ctx context.Context, pkg string) ([]regtypes.Candidate, error) {
	var raw []byte

	if err := h.get(ctx, h.base.GoProxy+"/"+pkg+"/@v/list", &raw); err != nil {
		return nil, fmt.Errorf("listing go module %s: %w", pkg, err)
	}

	var out []regtypes.Candidate

	for _, line := range splitLines(raw) {
		var info struct {
			Version string    `json:"Version"`
			Time    time.Time `json:"Time"`
		}

		if err := h.getJSON(ctx, h.base.GoProxy+"/"+pkg+"/@v/"+line+".info", &info); err != nil {
			return nil, fmt.Errorf("reading go module %s@%s: %w", pkg, line, err)
		}

		out = append(out, regtypes.Candidate{Version: info.Version, ReleasedAt: info.Time})
	}

	return out, nil
}

func (h *HTTP) crateVersions(ctx context.Context, pkg string) ([]regtypes.Candidate, error) {
	var body struct {
		Versions []struct {
			Num       string    `json:"num"`
			CreatedAt time.Time `json:"created_at"`
			Yanked    bool      `json:"yanked"`
		} `json:"versions"`
	}

	if err := h.getJSON(ctx, h.base.Crates+"/api/v1/crates/"+url.PathEscape(pkg), &body); err != nil {
		return nil, fmt.Errorf("listing crate %s: %w", pkg, err)
	}

	var out []regtypes.Candidate

	for _, v := range body.Versions {
		if v.Yanked {
			continue
		}

		out = append(out, regtypes.Candidate{Version: v.Num, ReleasedAt: v.CreatedAt})
	}

	return out, nil
}

func (h *HTTP) pypiVersions(ctx context.Context, pkg string) ([]regtypes.Candidate, error) {
	var body struct {
		Releases map[string][]struct {
			UploadTime time.Time `json:"upload_time_iso_8601"`
			Yanked     bool      `json:"yanked"`
		} `json:"releases"`
	}

	if err := h.getJSON(ctx, h.base.PyPI+"/pypi/"+url.PathEscape(pkg)+"/json", &body); err != nil {
		return nil, fmt.Errorf("listing python package %s: %w", pkg, err)
	}

	var out []regtypes.Candidate

	for version, files := range body.Releases {
		if len(files) == 0 || files[0].Yanked {
			continue
		}

		out = append(out, regtypes.Candidate{Version: version, ReleasedAt: files[0].UploadTime})
	}

	return out, nil
}

func (h *HTTP) npmVersions(ctx context.Context, pkg string) ([]regtypes.Candidate, error) {
	var body struct {
		Time map[string]time.Time `json:"time"`
	}

	if err := h.getJSON(ctx, h.base.NPM+"/"+url.PathEscape(pkg), &body); err != nil {
		return nil, fmt.Errorf("listing npm package %s: %w", pkg, err)
	}

	var out []regtypes.Candidate

	for version, at := range body.Time {
		if version == "created" || version == "modified" {
			continue
		}

		out = append(out, regtypes.Candidate{Version: version, ReleasedAt: at})
	}

	return out, nil
}

// userAgent identifies us to every registry we read.
//
// crates.io answers 403 to a request that does not send one. That 403 was
// read as "the network blocks crates.io", which is how this repo grew a local
// stand-in translating the sparse index into the API shape, and how rust
// entries ended up with no release dates. One header, and the real API
// answers 200.
const userAgent = "forge-register (+https://github.com/alexandremahdhaoui/forge-register)"

func (h *HTTP) get(ctx context.Context, u string, raw *[]byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", u, err)
	}

	req.Header.Set("User-Agent", userAgent)

	res, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", u, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: status %d", u, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading %s: %w", u, err)
	}

	*raw = body

	return nil
}

func (h *HTTP) getJSON(ctx context.Context, u string, out any) error {
	var raw []byte
	if err := h.get(ctx, u, &raw); err != nil {
		return err
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s: %w", u, err)
	}

	return nil
}

func splitLines(raw []byte) []string {
	var out []string

	start := 0
	for i, b := range raw {
		if b == '\n' {
			if i > start {
				out = append(out, string(raw[start:i]))
			}

			start = i + 1
		}
	}

	if start < len(raw) {
		out = append(out, string(raw[start:]))
	}

	return out
}

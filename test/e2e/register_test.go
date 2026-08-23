//go:build e2e

// The whole loop, hermetic: the real forge-register binary, the real
// ci-state-git committing to a real git repo, and fake upstreams. No network
// beyond the module cache.
package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "forge-register-e2e")
	if err != nil {
		panic(err)
	}

	for _, target := range []string{
		"./cmd/forge-register",
		"github.com/alexandremahdhaoui/forge-ci/cmd/ci-state-git",
	} {
		build := exec.Command("go", "build", "-o", dir, target)
		build.Dir = repoRoot()
		build.Stderr = os.Stderr

		if err := build.Run(); err != nil {
			panic("building " + target + ": " + err.Error())
		}
	}

	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		panic(err)
	}

	code := m.Run()

	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	return filepath.Dir(filepath.Dir(wd))
}

// upstream fakes crates.io and OSV for one crate, mutable between runs.
type upstream struct {
	mu       sync.Mutex
	versions []map[string]any
	vulns    map[string][]string // version -> vuln ids
	severity map[string]string   // vuln id -> severity
}

func (u *upstream) release(version, createdAt string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.versions = append(u.versions, map[string]any{"num": version, "created_at": createdAt})
}

func (u *upstream) disclose(version, id, severity string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.vulns[version] = append(u.vulns[version], id)
	u.severity[id] = severity
}

func (u *upstream) serve(t *testing.T) string {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/crates/", func(w http.ResponseWriter, _ *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"versions": u.versions})
	})

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()

		var in struct {
			Queries []struct {
				Version string `json:"version"`
			} `json:"queries"`
		}

		_ = json.NewDecoder(r.Body).Decode(&in)

		results := make([]map[string]any, 0, len(in.Queries))

		for _, q := range in.Queries {
			ids := []map[string]any{}
			for _, id := range u.vulns[q.Version] {
				ids = append(ids, map[string]any{"id": id})
			}

			results = append(results, map[string]any{"vulns": ids})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()

		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"database_specific": map[string]any{"severity": u.severity[id]},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL
}

type instance struct {
	dir    string
	config string
}

func newInstance(t *testing.T, upstreamURL string) instance {
	t.Helper()

	dir := t.TempDir()

	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "config", "user.email", "e2e@example.invalid")
	run(t, dir, "git", "config", "user.name", "e2e")

	config := filepath.Join(dir, "forge-register.yaml")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf(`
name: e2e-register
state:
  engine: forge://github.com/alexandremahdhaoui/forge-ci/cmd/ci-state-git
  spec:
    path: %s
registries:
  crates: %s
osv:
  base: %s
params:
  quarantineDays: 0
  admissionMaxSeverity: critical
  deprecateAfterDays: 30
  staleAfterDays: 180
  deprecatedGraceDays: 30
  maxTracksPerPackage: 2
`, dir, upstreamURL, upstreamURL)), 0o600))

	return instance{dir: dir, config: config}
}

func (i instance) forgeRegister(t *testing.T, args ...string) (string, error) {
	t.Helper()

	// The flag package stops at the first positional, so flags go right
	// after the verb.
	full := append([]string{args[0], "--config", i.config}, args[1:]...)
	cmd := exec.Command("forge-register", full...)
	cmd.Dir = i.dir

	out, err := cmd.CombinedOutput()

	return string(out), err
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %v: %s", name, args, out)
}

func gitLog(t *testing.T, dir string) string {
	t.Helper()

	cmd := exec.Command("git", "log", "--format=%s")
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)

	return string(out)
}

func TestTheWholeLoop(t *testing.T) {
	up := &upstream{vulns: map[string][]string{}, severity: map[string]string{}}
	up.release("1.0.0", "2026-01-01T00:00:00Z")

	reg := newInstance(t, up.serve(t))

	// A request files; the index is untouched until the pipeline answers it.
	out, err := reg.forgeRegister(t, "add", "--reason", "the workspace needs it", "rust:example-crate")
	require.NoError(t, err, out)
	require.Contains(t, out, "filed")
	require.NoDirExists(t, filepath.Join(reg.dir, "index"))

	// The pipeline answers: admitted, track written, committed by the engine.
	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "adopted")

	trackPath := filepath.Join(reg.dir, "index", "rust", "example-crate", "1.json")
	require.FileExists(t, trackPath)

	raw, _ := os.ReadFile(trackPath)
	require.Contains(t, string(raw), `"current":"1.0.0"`)
	require.Contains(t, gitLog(t, reg.dir), "ci: index rust/example-crate/1")

	// Nothing new: the next run says so rather than staying silent.
	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "up-to-date")

	// Upstream releases a newer version: adopted (quarantine 0).
	up.release("1.1.0", "2026-02-01T00:00:00Z")

	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "adopted")

	raw, _ = os.ReadFile(trackPath)
	require.Contains(t, string(raw), `"current":"1.1.0"`)

	// A worse release appears: held, with the verdict saying why.
	up.release("1.2.0", "2026-03-01T00:00:00Z")
	up.disclose("1.2.0", "RUSTSEC-2026-0001", "HIGH")

	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "held-worse-vector")

	raw, _ = os.ReadFile(trackPath)
	require.Contains(t, string(raw), `"current":"1.1.0"`, "a worse release does not advance the track")

	// The current version itself gains a critical, and the next release
	// fixes it: security upgrade, and the advisory never sticks.
	up.disclose("1.1.0", "RUSTSEC-2026-0002", "CRITICAL")
	up.release("1.2.1", "2026-03-02T00:00:00Z")

	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "security upgrade")

	raw, _ = os.ReadFile(trackPath)
	require.Contains(t, string(raw), `"current":"1.2.1"`)

	// Status reads it all back.
	out, err = reg.forgeRegister(t, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "rust:example-crate track 1 at 1.2.1")
}

func TestARejectionExplainsItself(t *testing.T) {
	up := &upstream{vulns: map[string][]string{}, severity: map[string]string{}}
	up.release("2.0.0", "2026-01-01T00:00:00Z")
	up.disclose("2.0.0", "CVE-2026-9999", "CRITICAL")

	reg := newInstance(t, up.serve(t))

	out, err := reg.forgeRegister(t, "add", "--reason", "needed", "rust:example-crate")
	require.NoError(t, err, out)

	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "denied-over-floor")
	require.Contains(t, out, "critical")
	require.NoDirExists(t, filepath.Join(reg.dir, "index"), "a denial never touches the index")

	// The verdict is recorded, so a second run does not re-answer.
	out, err = reg.forgeRegister(t, "apply")
	require.NoError(t, err, out)
	require.Contains(t, out, "process: 0 verdicts")
}

func TestPublishIsTheProofDoor(t *testing.T) {
	up := &upstream{vulns: map[string][]string{}, severity: map[string]string{}}
	reg := newInstance(t, up.serve(t))

	out, err := reg.forgeRegister(t, "publish", "--provenance", "213ecaf37e78",
		"--source", "git@github.com:example/golden-spec.git", "internal:github.com/example/golden-spec", "0.3.0")
	require.NoError(t, err, out)
	require.Contains(t, out, "adopted")

	trackPath := filepath.Join(reg.dir, "index", "internal", "github.com", "example", "golden-spec", "0.json")
	require.FileExists(t, trackPath)

	raw, _ := os.ReadFile(trackPath)
	require.Contains(t, string(raw), `"provenance":"213ecaf37e78"`)
}

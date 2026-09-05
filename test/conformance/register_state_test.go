//go:build conformance

// The register ships no state engine: it rides forge-ci's ci-state-git with
// its kinds named in the engine spec. This suite proves both halves against
// the real binary over real MCP - the ten transport vectors every state
// engine must pass, and the register kinds on top of them.
package conformance_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/engineadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

const (
	vectorPath = "../../.forge/spec-cache/revision/cases.json"

	// The workspace's ci-state-git: built by TestMain onto PATH, so the
	// resolver's LookPath finds the checkout's build rather than a stale tag.
	stateEngine = "forge://github.com/alexandremahdhaoui/forge-ci/cmd/ci-state-git"
)

type op struct {
	Tool      string         `json:"tool"`
	In        map[string]any `json:"in"`
	Want      map[string]any `json:"want"`
	WantError string         `json:"wantError"`
}

type transportCase struct {
	Case string `json:"case"`
	Why  string `json:"why"`
	Ops  []op   `json:"ops"`
}

type vectors struct {
	Transport []transportCase `json:"transport"`
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "forge-register-conformance")
	if err != nil {
		panic(err)
	}

	// The sibling checkout wins, the same rule resolve-spec applies to a
	// spec: in a factory whose members declare no language there is no
	// go.work to lend forge-ci's packages to this module, and the module
	// path form found nothing (forge-self run 90). Without a sibling, the
	// enclosing workspace resolves the path as before.
	build := exec.Command("go", "build", "-o", dir,
		"github.com/alexandremahdhaoui/forge-ci/cmd/ci-state-git")
	build.Dir = repoRoot()

	if sibling := filepath.Join(repoRoot(), "..", "forge-ci"); fileExists(filepath.Join(sibling, "go.mod")) {
		build = exec.Command("go", "build", "-C", sibling, "-o", dir, "./cmd/ci-state-git")
	}

	build.Stderr = os.Stderr

	if err := build.Run(); err != nil {
		panic("building the workspace ci-state-git: " + err.Error())
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

func fileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && !info.IsDir()
}

func load(t *testing.T) vectors {
	t.Helper()

	raw, err := os.ReadFile(vectorPath)
	require.NoError(t, err, "run the resolve-spec build stage first")

	var v vectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Transport, "the contract has no transport vectors")

	return v
}

// TestTheStateEngineSatisfiesTheTransportContract runs forge-revision-spec's
// vectors with the register kinds injected, proving the extra kinds change
// nothing the contract pins.
func TestTheStateEngineSatisfiesTheTransportContract(t *testing.T) {
	caller := engineadapter.NewMCPCaller("", "conformance", os.Stderr)

	for _, c := range load(t).Transport {
		t.Run(c.Case, func(t *testing.T) {
			store := t.TempDir()

			for i, o := range c.Ops {
				in := map[string]any{"spec": map[string]any{
					"path":  store,
					"kinds": []any{"index", "request", "verdict"},
				}}
				for k, v := range o.In {
					in[k] = v
				}

				var got map[string]any

				err := caller.Call(context.Background(), stateEngine, o.Tool, in, &got)

				if o.WantError != "" {
					require.Error(t, err, "op %d: %s", i, c.Why)
					require.Contains(t, err.Error(), o.WantError, "op %d", i)

					continue
				}

				require.NoError(t, err, "op %d: %s", i, c.Why)

				for key, want := range o.Want {
					require.EqualValues(t, want, got[key],
						"op %d wanted %s to be %v: %s", i, key, want, c.Why)
				}
			}
		})
	}
}

// TestRegisterRecordsRideTheRealEngine drives the typed store against the
// real binary: a track round-trips at its nested key, listing walks the tree,
// and a request stops being pending the moment its verdict is written.
func TestRegisterRecordsRideTheRealEngine(t *testing.T) {
	ctx := context.Background()
	caller := engineadapter.NewMCPCaller("", "conformance", os.Stderr)
	store := storeadapter.New(caller, stateEngine, map[string]any{"path": t.TempDir()})

	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	track := regtypes.Track{
		Package: "github.com/example/pkg", Ecosystem: "go", Prefix: "1",
		Current: "1.2.0", UpdatedAt: at,
		ReleasedAt: at, AdoptedAt: at, OSVSnapshot: "sha256:snap",
		Outcome: regtypes.OutcomeClean,
		Reason:  "the feed carries 3 record(s) for github.com/example/pkg and none of their ranges cover 1.2.0",
	}

	require.NoError(t, store.PutTrack(ctx, track))

	got, found, err := store.Track(ctx, "go", "github.com/example/pkg", "1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, track, got)

	_, found, err = store.Track(ctx, "go", "github.com/example/pkg", "2")
	require.NoError(t, err)
	require.False(t, found, "a missing record is found false, never an error")

	other := track
	other.Ecosystem = "rust"
	other.Package = "example-crate"
	require.NoError(t, store.PutTrack(ctx, other))

	all, err := store.Tracks(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2, "listing walks the nested keys")

	narrowed, err := store.TracksOf(ctx, "go", "github.com/example/pkg")
	require.NoError(t, err)
	require.Len(t, narrowed, 1)

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
		Reason: "conformance", CreatedAt: at,
	}
	require.NoError(t, store.PutRequest(ctx, "rust/example-crate/1-admission", request))

	pending, err := store.PendingRequests(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1)

	require.NoError(t, store.PutVerdict(ctx, "rust/example-crate/1-admission", regtypes.Verdict{
		Code: regtypes.VerdictAdopted, Package: "example-crate", DecidedAt: at,
	}))

	pending, err = store.PendingRequests(ctx)
	require.NoError(t, err)
	require.Empty(t, pending, "answering a request is writing its verdict")
}

package clidriver_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/registercontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/driver/clidriver"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/discoverycontrollermock"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/storeadaptermock"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
	"github.com/alexandremahdhaoui/forge-register/pkg/config"
)

var now = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

const configYAML = `
name: test-register
state:
  engine: go://example.com/state
  spec:
    path: .
params:
  quarantineDays: 0
  admissionMaxSeverity: critical
  deprecateAfterDays: 30
  staleAfterDays: 180
  deprecatedGraceDays: 30
  maxTracksPerPackage: 2
`

type harness struct {
	out       *bytes.Buffer
	store     *storeadaptermock.MockStore
	discovery *discoverycontrollermock.MockDiscoverer
	driver    *clidriver.Driver
}

func newHarness(t *testing.T) harness {
	t.Helper()

	out := &bytes.Buffer{}
	store := storeadaptermock.NewMockStore(t)
	discovery := discoverycontrollermock.NewMockDiscoverer(t)

	driver := clidriver.New(clidriver.Deps{
		Out:      out,
		ReadFile: func(string) ([]byte, error) { return []byte(configYAML), nil },
		Now:      func() time.Time { return now },
		Build: func(cfg config.Register) (*registercontroller.Controller, storeadapter.Store, error) {
			params := regtypes.Params{
				QuarantineDays:       cfg.Params.QuarantineDays,
				AdmissionMaxSeverity: regtypes.Severity(cfg.Params.AdmissionMaxSeverity),
				DeprecateAfterDays:   cfg.Params.DeprecateAfterDays,
				StaleAfterDays:       cfg.Params.StaleAfterDays,
				DeprecatedGraceDays:  cfg.Params.DeprecatedGraceDays,
				MaxTracksPerPackage:  cfg.Params.MaxTracksPerPackage,
			}

			return registercontroller.New(store, discovery, params), store, nil
		},
	})

	return harness{out: out, store: store, discovery: discovery, driver: driver}
}

func TestValidateDescribesTheRegister(t *testing.T) {
	h := newHarness(t)

	require.NoError(t, h.driver.Run(context.Background(), []string{"validate"}))
	require.Contains(t, h.out.String(), "test-register")
	require.Contains(t, h.out.String(), "floor critical")
}

func TestAddFilesARequestAndNeverWritesTheIndex(t *testing.T) {
	h := newHarness(t)

	var (
		key   string
		filed regtypes.Request
	)

	h.store.EXPECT().PutRequest(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, k string, r regtypes.Request) { key, filed = k, r }).
		Return(nil).Once()

	require.NoError(t, h.driver.Run(context.Background(),
		[]string{"add", "--reason", "needed by the workspace", "rust:example-crate"}))

	require.Equal(t, "example-crate", filed.Package)
	require.Equal(t, "rust", filed.Ecosystem)
	require.Contains(t, h.out.String(), key)
	// No PutTrack expectation: filing a request must not touch the index.
}

func TestAddWithoutAReasonIsUsage(t *testing.T) {
	h := newHarness(t)

	err := h.driver.Run(context.Background(), []string{"add", "rust:example-crate"})
	require.ErrorIs(t, err, clidriver.ErrUsage)
	require.ErrorContains(t, err, "config error, not a warning")
}

func TestApplyAnswersRequestsThenEvaluates(t *testing.T) {
	h := newHarness(t)

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
		Reason: "needed", CreatedAt: now,
	}

	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{"rust/example-crate/1-admission": request}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "rust", "example-crate").
		Return([]regtypes.Candidate{{Version: "1.0.0", ReleasedAt: now.Add(-24 * time.Hour)}}, "sha256:s", nil).Twice()
	h.store.EXPECT().Track(mock.Anything, "rust", "example-crate", "1").
		Return(regtypes.Track{}, false, nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Twice()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()
	h.store.EXPECT().Tracks(mock.Anything).
		Return([]regtypes.Track{{
			Package: "example-crate", Ecosystem: "rust", Prefix: "1", Current: "1.0.0",
		}}, nil).Once()

	require.NoError(t, h.driver.Run(context.Background(), []string{"apply"}))
	require.Contains(t, h.out.String(), "process: 1 verdicts, 1 adopted")
	require.Contains(t, h.out.String(), "evaluate: 1 verdicts, 0 adopted")
}

func TestStatusReadsTracksAndPending(t *testing.T) {
	h := newHarness(t)

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{{
		Package: "serde", Ecosystem: "rust", Prefix: "1", Current: "1.0.221",
		Advisory: &regtypes.Advisory{
			VulnIDs: []string{"RUSTSEC-1"}, Severity: regtypes.SeverityLow, Since: now,
		},
		Deprecated: &regtypes.Deprecation{Reason: regtypes.DeprecationStale, Since: now},
	}}, nil).Once()
	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{}, nil).Once()

	require.NoError(t, h.driver.Run(context.Background(), []string{"status"}))
	require.Contains(t, h.out.String(), "ADVISORY low")
	require.Contains(t, h.out.String(), "DEPRECATED (stale)")
	require.Contains(t, h.out.String(), "1 tracks, 0 pending")
}

func TestPublishNeedsProvenance(t *testing.T) {
	h := newHarness(t)

	err := h.driver.Run(context.Background(),
		[]string{"publish", "internal:github.com/example/spec", "0.3.0"})
	require.ErrorIs(t, err, clidriver.ErrUsage)
	require.ErrorContains(t, err, "proof door")
}

func TestPublishRecordsTheProof(t *testing.T) {
	h := newHarness(t)

	h.store.EXPECT().Track(mock.Anything, "internal", "github.com/example/spec", "0").
		Return(regtypes.Track{}, false, nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	require.NoError(t, h.driver.Run(context.Background(),
		[]string{"publish", "--provenance", "213ecaf37e78", "internal:github.com/example/spec", "0.3.0"}))
	require.Contains(t, h.out.String(), "213ecaf37e78")
}

func TestAnUnknownVerbIsUsage(t *testing.T) {
	h := newHarness(t)

	err := h.driver.Run(context.Background(), []string{"frobnicate"})
	require.ErrorIs(t, err, clidriver.ErrUsage)
	require.NotEmpty(t, clidriver.Usage())
}

func TestAnUnreadableConfigIsAnError(t *testing.T) {
	driver := clidriver.New(clidriver.Deps{
		Out:      &bytes.Buffer{},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Now:      func() time.Time { return now },
		Build: func(config.Register) (*registercontroller.Controller, storeadapter.Store, error) {
			return nil, nil, nil
		},
	})

	err := driver.Run(context.Background(), []string{"validate"})
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestEvaluateAndProcessRunAlone(t *testing.T) {
	h := newHarness(t)
	h.store.EXPECT().Tracks(mock.Anything).Return(nil, nil).Once()
	require.NoError(t, h.driver.Run(context.Background(), []string{"evaluate"}))

	h.store.EXPECT().PendingRequests(mock.Anything).Return(nil, nil).Once()
	require.NoError(t, h.driver.Run(context.Background(), []string{"process"}))
}

func TestNoVerbIsUsage(t *testing.T) {
	h := newHarness(t)
	require.ErrorIs(t, h.driver.Run(context.Background(), nil), clidriver.ErrUsage)
}

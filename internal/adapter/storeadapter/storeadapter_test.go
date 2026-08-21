package storeadapter_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/engineadaptermock"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

const uri = "go://example.com/state@v1"

// memory answers like a state engine: put remembers, get returns, list keys.
type memory struct {
	records map[string]map[string]string
}

func newMemory() *memory { return &memory{records: map[string]map[string]string{}} }

func (m *memory) call(_ context.Context, _ string, tool string, in, out any) error {
	raw, _ := json.Marshal(in)

	var req struct {
		Kind, Key, Payload string
		Spec               map[string]any
	}

	_ = json.Unmarshal(raw, &req)

	if m.records[req.Kind] == nil {
		m.records[req.Kind] = map[string]string{}
	}

	switch tool {
	case "put":
		m.records[req.Kind][req.Key] = req.Payload

		return fill(out, map[string]any{"found": true, "payload": req.Payload})
	case "get":
		payload, ok := m.records[req.Kind][req.Key]

		return fill(out, map[string]any{"found": ok, "payload": payload})
	case "list":
		keys := []string{}

		for k := range m.records[req.Kind] {
			if req.Key == "" || len(k) > len(req.Key) && k[:len(req.Key)] == req.Key {
				suffix := k
				if req.Key != "" {
					suffix = k[len(req.Key)+1:]
				}

				keys = append(keys, suffix)
			}
		}

		return fill(out, map[string]any{"keys": keys})
	}

	return nil
}

func fill(out any, value map[string]any) error {
	raw, _ := json.Marshal(value)

	return json.Unmarshal(raw, out)
}

func newStore(t *testing.T) (storeadapter.Store, *memory) {
	t.Helper()

	mem := newMemory()
	caller := engineadaptermock.NewMockCaller(t)
	caller.EXPECT().Call(mock.Anything, uri, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(mem.call).Maybe()

	return storeadapter.New(caller, uri, map[string]any{"path": "/tmp/x"}), mem
}

func TestATrackRoundTripsThroughTheWire(t *testing.T) {
	store, mem := newStore(t)

	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	track := regtypes.Track{
		Package: "serde", Ecosystem: "rust", Prefix: "1", Current: "1.0.221", UpdatedAt: at,
		History: []regtypes.Entry{{
			Version: "1.0.221", ReleasedAt: at, AdoptedAt: at,
			Vulns: regtypes.Vector{Low: 1}, OSVSnapshot: "sha256:2f7a",
		}},
		Advisory: &regtypes.Advisory{
			VulnIDs: []string{"RUSTSEC-1"}, Severity: regtypes.SeverityLow, Since: at,
		},
		Deprecated: &regtypes.Deprecation{Reason: regtypes.DeprecationStale, Since: at},
	}

	require.NoError(t, store.PutTrack(context.Background(), track))

	got, found, err := store.Track(context.Background(), "rust", "serde", "1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, track, got)

	// The payload on the wire is the spec's camelCase shape, as a string.
	payload := mem.records["index"]["rust/serde/1"]
	require.Contains(t, payload, `"updatedAt"`)
	require.Contains(t, payload, `"vulnIds"`)
}

func TestAMissingTrackIsNotAnError(t *testing.T) {
	store, _ := newStore(t)

	_, found, err := store.Track(context.Background(), "go", "example.com/pkg", "1")
	require.NoError(t, err)
	require.False(t, found)
}

func TestPendingRequestsAreThoseWithoutAVerdict(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	answered := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "a", Ecosystem: "go",
		Reason: "r", CreatedAt: at,
	}
	open := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "b", Ecosystem: "go",
		Reason: "r", CreatedAt: at,
	}

	require.NoError(t, store.PutRequest(ctx, "go/a/1-admission", answered))
	require.NoError(t, store.PutRequest(ctx, "go/b/1-admission", open))
	require.NoError(t, store.PutVerdict(ctx, "go/a/1-admission", regtypes.Verdict{
		Code: regtypes.VerdictAdopted, Package: "a", DecidedAt: at,
	}))

	pending, err := store.PendingRequests(ctx)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, open, pending["go/b/1-admission"])
}

func TestAVerdictRoundTripsWithItsAlternatives(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	verdict := regtypes.Verdict{
		Code: regtypes.VerdictDeniedOverFloor, Package: "example.com/pkg", Ecosystem: "go",
		Requested: "2.4.1",
		Alternatives: []regtypes.Alternative{{
			Version: "2.3.9", ReleasedAt: at, Vulns: regtypes.Vector{Medium: 1},
		}},
		OSVSnapshot: "sha256:9c1d",
		Message:     "2.4.1 carries a critical",
		DecidedAt:   at,
	}

	require.NoError(t, store.PutVerdict(ctx, "go/example.com/pkg/1-admission", verdict))

	got, found, err := store.Verdict(ctx, "go/example.com/pkg/1-admission")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, verdict, got)
}

func TestTheKindsTravelInTheSpec(t *testing.T) {
	caller := engineadaptermock.NewMockCaller(t)

	var spec map[string]any

	caller.EXPECT().Call(mock.Anything, uri, "get", mock.Anything, mock.Anything).
		Run(func(_ context.Context, _, _ string, in, _ any) {
			raw, _ := json.Marshal(in)

			var req struct {
				Spec map[string]any `json:"spec"`
			}

			_ = json.Unmarshal(raw, &req)
			spec = req.Spec
		}).
		RunAndReturn(func(_ context.Context, _, _ string, _, out any) error {
			return fill(out, map[string]any{"found": false})
		}).Once()

	store := storeadapter.New(caller, uri, map[string]any{"path": "/tmp/x"})
	_, _, err := store.Track(context.Background(), "go", "p", "1")
	require.NoError(t, err)

	require.Equal(t, "/tmp/x", spec["path"])
	require.ElementsMatch(t, []any{"index", "request", "verdict"}, spec["kinds"],
		"the register kinds ride in the engine spec, so the engine never learns what they mean")
}

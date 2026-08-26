package registercontroller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/controller/registercontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/discoverycontrollermock"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/storeadaptermock"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

var now = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

func params() regtypes.Params {
	return regtypes.Params{
		QuarantineDays:       0,
		AdmissionMaxSeverity: regtypes.SeverityCritical,
		DeprecateAfterDays:   30,
		StaleAfterDays:       180,
		DeprecatedGraceDays:  30,
		MaxTracksPerPackage:  2,
	}
}

type harness struct {
	store     *storeadaptermock.MockStore
	discovery *discoverycontrollermock.MockDiscoverer
	c         *registercontroller.Controller
}

func newHarness(t *testing.T) harness {
	t.Helper()

	store := storeadaptermock.NewMockStore(t)
	discovery := discoverycontrollermock.NewMockDiscoverer(t)

	return harness{
		store:     store,
		discovery: discovery,
		c:         registercontroller.New(store, discovery, params()),
	}
}

func TestEvaluateAdvancesATrackAndWritesTheVerdict(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.0.0",
		History: []regtypes.Entry{{Version: "1.0.0"}},
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{Version: "1.1.0", ReleasedAt: days(30)}}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	var verdict regtypes.Verdict

	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ string, v regtypes.Verdict) { verdict = v }).Return(nil).Once()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted)

	require.Equal(t, "1.1.0", written.Current)
	require.Len(t, written.History, 2)
	require.Equal(t, "sha256:snap", written.History[1].OSVSnapshot)

	require.Equal(t, regtypes.VerdictAdopted, verdict.Code)
	require.Equal(t, "sha256:snap", verdict.OSVSnapshot)
}

func TestEvaluateWritesUpToDateRatherThanSilence(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0"}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{Version: "1.1.0", ReleasedAt: days(90)}}, "sha256:snap", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Once()

	var verdict regtypes.Verdict

	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ string, v regtypes.Verdict) { verdict = v }).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, regtypes.VerdictUpToDate, verdict.Code)
}

func TestEvaluateRaisesAndClearsAnAdvisory(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0"}

	// Current gains a vulnerability and no fixed release exists: the track
	// keeps its current, and an advisory appears.
	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{
			{
				Version: "1.1.0", ReleasedAt: days(90),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"CVE-9"},
			},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(2)

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Advisory)
	require.Equal(t, []string{"CVE-9"}, written.Advisory.VulnIDs)
	require.Equal(t, regtypes.SeverityHigh, written.Advisory.Severity)

	// The fix appears: the track adopts it and the advisory clears.
	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{written}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{
			{
				Version: "1.1.0", ReleasedAt: days(90),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"CVE-9"},
			},
			{Version: "1.1.1", ReleasedAt: days(0)},
		}, "sha256:snap2", nil).Once()

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted, "a security fix adopts with quarantine waived")
	require.Equal(t, "1.1.1", written.Current)
	require.Nil(t, written.Advisory)
}

func TestProcessAdmitsANewPackage(t *testing.T) {
	h := newHarness(t)

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
		Reason: "needed", CreatedAt: now,
	}
	key := registercontroller.RequestKey(request, now)

	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{key: request}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "rust", "example-crate").
		Return([]regtypes.Candidate{{Version: "1.0.0", ReleasedAt: days(30)}}, "sha256:snap", nil).Once()
	h.store.EXPECT().Track(mock.Anything, "rust", "example-crate", "1").
		Return(regtypes.Track{}, false, nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	var verdict regtypes.Verdict

	h.store.EXPECT().PutVerdict(mock.Anything, key, mock.Anything).
		Run(func(_ context.Context, _ string, v regtypes.Verdict) { verdict = v }).Return(nil).Once()

	report, err := h.c.Process(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted)
	require.Equal(t, regtypes.VerdictAdopted, verdict.Code)
	require.Equal(t, "1.0.0", written.Current)
	require.Equal(t, "1", written.Prefix)
}

func TestProcessRejectsWithoutTouchingTheIndex(t *testing.T) {
	h := newHarness(t)

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
		Version: "9.9.9", Reason: "needed", CreatedAt: now,
	}
	key := registercontroller.RequestKey(request, now)

	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{key: request}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "rust", "example-crate").
		Return([]regtypes.Candidate{{Version: "1.0.0", ReleasedAt: days(30)}}, "sha256:snap", nil).Once()

	var verdict regtypes.Verdict

	h.store.EXPECT().PutVerdict(mock.Anything, key, mock.Anything).
		Run(func(_ context.Context, _ string, v regtypes.Verdict) { verdict = v }).Return(nil).Once()

	report, err := h.c.Process(context.Background(), now)
	require.NoError(t, err)
	require.Zero(t, report.Adopted)
	require.Equal(t, regtypes.VerdictDeniedUnknown, verdict.Code)
	require.NotEmpty(t, verdict.Message, "a denial is correctable from its verdict alone")
}

func TestProcessOpensAMaintainedTrack(t *testing.T) {
	h := newHarness(t)

	request := regtypes.Request{
		Type: regtypes.RequestOpenTrack, Package: "example.com/pkg", Ecosystem: "go",
		Track: "1.27", Reason: "1.28 breaks the v1 config API", CreatedAt: now,
	}
	key := registercontroller.RequestKey(request, now)

	candidates := []regtypes.Candidate{
		{Version: "1.27.0", ReleasedAt: days(400)},
		{Version: "1.28.0", ReleasedAt: days(300)},
		{Version: "1.27.9", ReleasedAt: days(20)},
	}

	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{key: request}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return(candidates, "sha256:snap", nil).Once()
	h.store.EXPECT().TracksOf(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Track{{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.28.0"}}, nil).Once()
	h.store.EXPECT().Track(mock.Anything, "go", "example.com/pkg", "1.27").
		Return(regtypes.Track{}, false, nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, key, mock.Anything).Return(nil).Once()

	report, err := h.c.Process(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted)
	require.Equal(t, "1.27", written.Prefix)
	require.Equal(t, "1.27.9", written.Current, "a maintenance track opens at the line's head")
}

func TestPublishIsTheProofDoor(t *testing.T) {
	h := newHarness(t)

	h.store.EXPECT().Track(mock.Anything, "internal", "github.com/example/spec", "0").
		Return(regtypes.Track{}, false, nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	kv, err := h.c.Publish(context.Background(), "internal", "github.com/example/spec",
		"0.3.0", "git@github.com:example/spec.git", "213ecaf37e78", now)
	require.NoError(t, err)
	require.Equal(t, regtypes.VerdictAdopted, kv.Verdict.Code)
	require.Contains(t, kv.Verdict.Message, "213ecaf37e78")

	require.Equal(t, "0.3.0", written.Current)
	require.Equal(t, "213ecaf37e78", written.History[0].Provenance)
}

func TestPublishOfAnOlderVersionMovesNothing(t *testing.T) {
	h := newHarness(t)

	h.store.EXPECT().Track(mock.Anything, "internal", "github.com/example/spec", "0").
		Return(regtypes.Track{
			Package: "github.com/example/spec", Ecosystem: "internal", Prefix: "0", Current: "0.3.0",
		}, true, nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	kv, err := h.c.Publish(context.Background(), "internal", "github.com/example/spec",
		"0.2.0", "", "abc", now)
	require.NoError(t, err)
	require.Equal(t, regtypes.VerdictUpToDate, kv.Verdict.Code)
}

func TestAnAdvisoryNamesItsHighestSeverity(t *testing.T) {
	for _, tc := range []struct {
		vector regtypes.Vector
		want   regtypes.Severity
	}{
		{regtypes.Vector{Critical: 1, Low: 3}, regtypes.SeverityCritical},
		{regtypes.Vector{Medium: 2}, regtypes.SeverityMedium},
		{regtypes.Vector{Low: 1}, regtypes.SeverityLow},
	} {
		h := newHarness(t)
		track := regtypes.Track{Package: "p", Ecosystem: "go", Prefix: "1", Current: "1.0.0"}

		h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
		h.discovery.EXPECT().Discover(mock.Anything, "go", "p").
			Return([]regtypes.Candidate{
				{Version: "1.0.0", ReleasedAt: days(90), Vulns: tc.vector, VulnIDs: []string{"V"}},
			}, "s", nil).Once()

		var written regtypes.Track

		h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
			Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
		h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		_, err := h.c.Evaluate(context.Background(), now)
		require.NoError(t, err)
		require.NotNil(t, written.Advisory)
		require.Equal(t, tc.want, written.Advisory.Severity)
	}
}

func TestAnAdmissionBehindTheTrackMovesNothing(t *testing.T) {
	h := newHarness(t)

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
		Version: "1.0.0", Reason: "needed", CreatedAt: now,
	}
	key := registercontroller.RequestKey(request, now)

	h.store.EXPECT().PendingRequests(mock.Anything).
		Return(map[string]regtypes.Request{key: request}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "rust", "example-crate").
		Return([]regtypes.Candidate{
			{Version: "1.0.0", ReleasedAt: days(90)},
			{Version: "1.2.0", ReleasedAt: days(60)},
		}, "s", nil).Once()
	h.store.EXPECT().Track(mock.Anything, "rust", "example-crate", "1").
		Return(regtypes.Track{
			Package: "example-crate", Ecosystem: "rust", Prefix: "1", Current: "1.2.0",
		}, true, nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, key, mock.Anything).Return(nil).Once()

	// No PutTrack expectation: the track is already ahead of the adoption.
	_, err := h.c.Process(context.Background(), now)
	require.NoError(t, err)
}

func TestAFeedFailureHidesNoOtherTrack(t *testing.T) {
	h := newHarness(t)

	broken := regtypes.Track{Package: "gone", Ecosystem: "go", Prefix: "1", Current: "1.0.0"}
	fine := regtypes.Track{Package: "p", Ecosystem: "rust", Prefix: "1", Current: "1.0.0"}
	internal := regtypes.Track{Package: "spec", Ecosystem: "internal", Prefix: "0", Current: "0.2.0"}

	h.store.EXPECT().Tracks(mock.Anything).
		Return([]regtypes.Track{broken, fine, internal}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "gone").
		Return(nil, "", errors.New("status 404")).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "rust", "p").
		Return([]regtypes.Candidate{{Version: "1.0.0", ReleasedAt: days(90)}}, "s", nil).Once()
	// Internal versions still enter only by proof, but their vectors are
	// refreshed over the published history like every other track's.
	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "spec", mock.Anything).
		Return([]regtypes.Candidate{}, "s2", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Twice()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Len(t, report.Failed, 1)
	require.Contains(t, report.Failed[0], "go:gone")
	require.Len(t, report.Verdicts, 2, "the broken feed hides nothing")
}

// A published fix advances an internal track the moment its vector
// improves: the fast-adopt the policy always had, now reachable for
// versions that entered by proof. Only the pointer moves - a second
// history entry would shadow the provenance the published one carries.
func TestAnInternalTrackFastAdoptsAPublishedFix(t *testing.T) {
	h := newHarness(t)

	vulnerable := regtypes.Entry{
		Version: "v0.1.0-dev.r00000001.gaaaaaaaaaaaa", ReleasedAt: days(30),
		Provenance: "aaaaaaaaaaaa",
	}
	fixed := regtypes.Entry{
		Version: "v0.1.0-dev.r00000002.gbbbbbbbbbbbb", ReleasedAt: days(1),
		Provenance: "bbbbbbbbbbbb",
	}

	track := regtypes.Track{
		Package: "example.com/toolchain-member", Ecosystem: "internal", Prefix: "0",
		Current: vulnerable.Version,
		History: []regtypes.Entry{vulnerable, fixed},
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "example.com/toolchain-member", mock.Anything).
		Return([]regtypes.Candidate{
			{Version: vulnerable.Version, ReleasedAt: days(30), Vulns: regtypes.Vector{High: 1}},
			{Version: fixed.Version, ReleasedAt: days(1), Vulns: regtypes.Vector{}},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted)
	require.Contains(t, report.Verdicts[0].Verdict.Message, "security upgrade")
	require.Contains(t, report.Verdicts[0].Verdict.Message, "quarantine waived")

	require.Equal(t, fixed.Version, written.Current)
	require.Len(t, written.History, 2, "adoption moves the pointer, never duplicates history")
	require.Equal(t, "bbbbbbbbbbbb", written.History[1].Provenance,
		"the published entry keeps its provenance")
	require.Nil(t, written.Advisory, "the adopted version is clean")
}

// A fresh disclosure on an internal current raises the advisory - the loud
// signal every consumer sync trips over, pins notwithstanding.
func TestAnInternalDisclosureRaisesTheAdvisory(t *testing.T) {
	h := newHarness(t)

	entry := regtypes.Entry{Version: "v0.1.0-dev.r00000001.gaaaaaaaaaaaa", ReleasedAt: days(30)}
	track := regtypes.Track{
		Package: "example.com/toolchain-member", Ecosystem: "internal", Prefix: "0",
		Current: entry.Version, History: []regtypes.Entry{entry},
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "example.com/toolchain-member", mock.Anything).
		Return([]regtypes.Candidate{
			{Version: entry.Version, ReleasedAt: days(30),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"GHSA-xxxx"}},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Advisory, "a disclosure on current must be loud")
	require.Equal(t, []string{"GHSA-xxxx"}, written.Advisory.VulnIDs)
}

func TestAPrereleaseLineIsNotASuccessor(t *testing.T) {
	h := newHarness(t)

	// Upstream's only life above 0.x is pre-releases and the 0.x line has
	// not released in over staleAfterDays: nothing exists to move to, so
	// the track must not deprecate as stale.
	track := regtypes.Track{
		Package: "httpx", Ecosystem: "python", Prefix: "0", Current: "0.28.1",
		History: []regtypes.Entry{{Version: "0.28.1"}},
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "python", "httpx").
		Return([]regtypes.Candidate{
			{Version: "0.28.1", ReleasedAt: days(300)},
			{Version: "1.0.dev5", ReleasedAt: days(10)},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Nil(t, written.Deprecated)

	// The moment 1.0 is a release, the stale rule may bite.
	h2 := newHarness(t)
	h2.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h2.discovery.EXPECT().Discover(mock.Anything, "python", "httpx").
		Return([]regtypes.Candidate{
			{Version: "0.28.1", ReleasedAt: days(300)},
			{Version: "1.0.0", ReleasedAt: days(10)},
		}, "sha256:snap", nil).Once()

	h2.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()
	h2.store.EXPECT().PutVerdict(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	_, err = h2.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Deprecated)
	require.Equal(t, regtypes.DeprecationStale, written.Deprecated.Reason)
}

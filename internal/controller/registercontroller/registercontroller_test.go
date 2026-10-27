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
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{Version: "1.1.0", ReleasedAt: days(30)}}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	var verdict regtypes.Verdict

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, 1, report.Adopted)

	require.Len(t, report.Verdicts, 1)
	verdict = report.Verdicts[0].Verdict

	require.Equal(t, "1.1.0", written.Current)
	require.Equal(t, "sha256:snap", written.OSVSnapshot)
	require.Equal(t, days(30), written.ReleasedAt)

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

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 1)
	require.Equal(t, regtypes.VerdictUpToDate, report.Verdicts[0].Verdict.Code,
		"an evaluation that changes nothing still says so, in the report")
}

func TestEvaluateRaisesAndClearsAnAdvisory(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0"}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{
			{
				Version: "1.1.0", ReleasedAt: days(90),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"CVE-9"},
				Outcome: regtypes.OutcomeFindings,
			},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Advisory)
	require.Equal(t, []string{"CVE-9"}, written.Advisory.VulnIDs)
	require.Equal(t, regtypes.SeverityHigh, written.Advisory.Severity)

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{written}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{
			{
				Version: "1.1.0", ReleasedAt: days(90),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"CVE-9"},
				Outcome: regtypes.OutcomeFindings,
			},
			{Version: "1.1.1", ReleasedAt: days(0), Outcome: regtypes.OutcomeClean},
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

func TestProcessAdmitsTheHigherVersionWhenDiscoveryReturnsTwoReleasesWithOneTimeInEitherOrder(t *testing.T) {
	assertProcessAdmits(t,
		regtypes.Candidate{Version: "0.27.3", ReleasedAt: days(30)},
		regtypes.Candidate{Version: "0.28.0", ReleasedAt: days(30)},
		"0", "0.28.0")
}

func TestProcessAdmitsTheHigherRawStringWhenDiscoveryReturnsTwoEqualVersionsInEitherOrder(t *testing.T) {
	assertProcessAdmits(t,
		regtypes.Candidate{Version: "1.2", ReleasedAt: days(30)},
		regtypes.Candidate{Version: "1.2.0", ReleasedAt: days(30)},
		"1", "1.2.0")
}

func assertProcessAdmits(t *testing.T, lower, higher regtypes.Candidate, prefix, want string) {
	t.Helper()

	for name, discovered := range map[string][]regtypes.Candidate{
		"lower-first":  {lower, higher},
		"higher-first": {higher, lower},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			request := regtypes.Request{
				Type: regtypes.RequestAdmission, Package: "example-crate", Ecosystem: "rust",
				Reason: "needed", CreatedAt: now,
			}
			key := registercontroller.RequestKey(request, now)

			h.store.EXPECT().PendingRequests(mock.Anything).
				Return(map[string]regtypes.Request{key: request}, nil).Once()
			h.discovery.EXPECT().Discover(mock.Anything, "rust", "example-crate").
				Return(discovered, "sha256:snap", nil).Once()
			h.store.EXPECT().Track(mock.Anything, "rust", "example-crate", prefix).
				Return(regtypes.Track{}, false, nil).Once()

			var written regtypes.Track

			h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
				Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

			var verdict regtypes.Verdict

			h.store.EXPECT().PutVerdict(mock.Anything, key, mock.Anything).
				Run(func(_ context.Context, _ string, v regtypes.Verdict) { verdict = v }).Return(nil).Once()

			_, err := h.c.Process(context.Background(), now)
			require.NoError(t, err)
			require.Equal(t, want, verdict.Adopted)
			require.Equal(t, want, written.Current)
		})
	}
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

	kv, err := h.c.Publish(context.Background(), "internal", "github.com/example/spec",
		"0.3.0", "git@github.com:example/spec.git", "213ecaf37e78", now)
	require.NoError(t, err)
	require.Equal(t, regtypes.VerdictAdopted, kv.Verdict.Code)
	require.Contains(t, kv.Verdict.Message, "213ecaf37e78")

	require.Equal(t, "0.3.0", written.Current)
	require.Equal(t, "213ecaf37e78", written.Provenance)
	require.Equal(t, "git@github.com:example/spec.git", written.Source)
}

func TestPublishOfAnOlderVersionMovesNothing(t *testing.T) {
	h := newHarness(t)

	h.store.EXPECT().Track(mock.Anything, "internal", "github.com/example/spec", "0").
		Return(regtypes.Track{
			Package: "github.com/example/spec", Ecosystem: "internal", Prefix: "0", Current: "0.3.0",
		}, true, nil).Once()

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
				{Version: "1.0.0", ReleasedAt: days(90), Vulns: tc.vector, VulnIDs: []string{"V"}, Outcome: regtypes.OutcomeFindings},
			}, "s", nil).Once()

		var written regtypes.Track

		h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
			Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

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
	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "spec", mock.Anything).
		Return([]regtypes.Candidate{}, "s2", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Twice()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Len(t, report.Failed, 1)
	require.Contains(t, report.Failed[0], "go:gone")
	require.Len(t, report.Verdicts, 2, "the broken feed hides nothing")
}

func TestAnInternalTrackWeighsOnlyTheVersionItIsOn(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "example.com/toolchain-member", Ecosystem: "internal", Prefix: "0",
		Current:    "v0.1.0-dev.r00000002.gbbbbbbbbbbbb",
		ReleasedAt: days(1),
		Provenance: "bbbbbbbbbbbb",
		Outcome:    regtypes.OutcomeClean,
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()

	var offered []regtypes.Candidate

	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "example.com/toolchain-member", mock.Anything).
		RunAndReturn(func(_ context.Context, _, _ string, published []regtypes.Candidate) ([]regtypes.Candidate, string, error) {
			offered = published

			return []regtypes.Candidate{{
				Version: track.Current, ReleasedAt: days(1), Outcome: regtypes.OutcomeClean,
			}}, "sha256:snap", nil
		}).Once()

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Maybe()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)

	require.Len(t, offered, 1)
	require.Equal(t, track.Current, offered[0].Version)
	require.Equal(t, days(1), offered[0].ReleasedAt)
}

func TestAnInternalDisclosureRaisesTheAdvisory(t *testing.T) {
	h := newHarness(t)

	const version = "v0.1.0-dev.r00000001.gaaaaaaaaaaaa"

	track := regtypes.Track{
		Package: "example.com/toolchain-member", Ecosystem: "internal", Prefix: "0",
		Current: version, ReleasedAt: days(30),
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Refresh(mock.Anything, "internal", "example.com/toolchain-member", mock.Anything).
		Return([]regtypes.Candidate{
			{
				Version: version, ReleasedAt: days(30),
				Vulns: regtypes.Vector{High: 1}, VulnIDs: []string{"GHSA-xxxx"}, Outcome: regtypes.OutcomeFindings,
			},
		}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Advisory, "a disclosure on current must be loud")
	require.Equal(t, []string{"GHSA-xxxx"}, written.Advisory.VulnIDs)
}

func TestAPrereleaseLineIsNotASuccessor(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "httpx", Ecosystem: "python", Prefix: "0", Current: "0.28.1",
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

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Nil(t, written.Deprecated)

	h2 := newHarness(t)
	h2.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h2.discovery.EXPECT().Discover(mock.Anything, "python", "httpx").
		Return([]regtypes.Candidate{
			{Version: "0.28.1", ReleasedAt: days(300)},
			{Version: "1.0.0", ReleasedAt: days(10)},
		}, "sha256:snap", nil).Once()

	h2.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	_, err = h2.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.NotNil(t, written.Deprecated)
	require.Equal(t, regtypes.DeprecationStale, written.Deprecated.Reason)
}

func TestAnAdvisoryCarriesTheFixTheScopeAndTheRealDate(t *testing.T) {
	h := newHarness(t)

	published := days(400)

	track := regtypes.Track{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0"}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{
			Version: "1.1.0", ReleasedAt: days(500),
			Vulns:           regtypes.Vector{High: 1},
			VulnIDs:         []string{"GHSA-real"},
			VulnSeverities:  []regtypes.Severity{regtypes.SeverityHigh},
			Outcome:         regtypes.OutcomeFindings,
			FixedIn:         []string{"1.2.0"},
			AffectedImports: []string{"example.com/pkg/inner"},
			PublishedAt:     published,
		}}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)

	require.NotNil(t, written.Advisory)
	require.Equal(t, []string{"1.2.0"}, written.Advisory.FixedIn,
		"upgrading is the best way out, so the version that fixes it has to travel")
	require.Equal(t, []string{"example.com/pkg/inner"}, written.Advisory.AffectedImports)
	require.Equal(t, published, written.Advisory.Since,
		"the advisory's own date, not ours: this also arms auto-deprecation")
	require.NotEqual(t, now, written.Advisory.Since)
}

func TestAnUnclassifiedFindingSaysUnknownRatherThanHigh(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{Package: "golang.org/x/crypto", Ecosystem: "go", Prefix: "0", Current: "v0.55.0"}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "golang.org/x/crypto").
		Return([]regtypes.Candidate{{
			Version: "v0.55.0", ReleasedAt: days(10),
			Vulns:          regtypes.Vector{High: 1},
			VulnIDs:        []string{"GO-2026-5932"},
			VulnSeverities: []regtypes.Severity{""},
			Outcome:        regtypes.OutcomeFindings,
			PublishedAt:    days(20),
		}}, "sha256:snap", nil).Once()

	var written regtypes.Track

	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
		Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

	_, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)

	require.NotNil(t, written.Advisory)
	require.Equal(t, regtypes.SeverityUnknown, written.Advisory.Severity)
	require.Empty(t, written.Advisory.FixedIn,
		"GO-2026-5932 has no fix and never will: the package is unmaintained by design")
}

func TestAnUnmeasuredVersionRaisesNoAdvisory(t *testing.T) {
	for _, outcome := range []regtypes.Outcome{regtypes.OutcomeNotFound, regtypes.OutcomeUnreachable} {
		t.Run(string(outcome), func(t *testing.T) {
			h := newHarness(t)

			track := regtypes.Track{Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0"}

			h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
			h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
				Return([]regtypes.Candidate{{
					Version: "1.1.0", ReleasedAt: days(10),
					Outcome: outcome, Reason: "nothing was measured",
				}}, "sha256:snap", nil).Once()

			var written regtypes.Track

			h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
				Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

			_, err := h.c.Evaluate(context.Background(), now)
			require.NoError(t, err)

			require.Nil(t, written.Advisory)
			require.Equal(t, outcome, written.Outcome,
				"the file has to say which kind of nothing this was")
			require.Equal(t, "nothing was measured", written.Reason)
		})
	}
}

func TestAFeedOutageNeverWithdrawsAnAdvisory(t *testing.T) {
	for _, outcome := range []regtypes.Outcome{regtypes.OutcomeUnreachable, regtypes.OutcomeNotFound} {
		t.Run(string(outcome), func(t *testing.T) {
			h := newHarness(t)

			standing := &regtypes.Advisory{
				VulnIDs: []string{"CVE-9"}, Severity: regtypes.SeverityCritical,
				Since: days(30), FixedIn: []string{"1.2.0"},
			}

			track := regtypes.Track{
				Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.1.0",
				Vulns: regtypes.Vector{Critical: 1}, Outcome: regtypes.OutcomeFindings,
				Advisory: standing,
			}

			h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
			h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
				Return([]regtypes.Candidate{{
					Version: "1.1.0", ReleasedAt: days(90),
					Outcome: outcome, Reason: "the vulnerability feed could not be reached",
				}}, "", nil).Once()

			var written regtypes.Track

			h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).
				Run(func(_ context.Context, tr regtypes.Track) { written = tr }).Return(nil).Once()

			_, err := h.c.Evaluate(context.Background(), now)
			require.NoError(t, err)

			require.NotNil(t, written.Advisory,
				"the feed said nothing, so the advisory has not been withdrawn")
			require.Equal(t, []string{"CVE-9"}, written.Advisory.VulnIDs)
			require.Equal(t, regtypes.SeverityCritical, written.Advisory.Severity)
			require.Equal(t, days(30), written.Advisory.Since, "and it keeps its own date")
		})
	}
}

func TestEvaluateCountsWhatTheRecordsSay(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "typescript", Ecosystem: "typescript", Prefix: "5", Current: "5.9.3",
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "typescript", "typescript").
		Return([]regtypes.Candidate{{
			Version: "5.9.3",
			Outcome: regtypes.OutcomeUnreachable,
			Reason:  "the vulnerability feed refused the request: too many queries",
		}}, "sha256:snap", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Maybe()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)

	require.Empty(t, report.Failed)

	require.Len(t, report.Unmeasured, 1)
	require.Contains(t, report.Unmeasured[0], "typescript:typescript")
	require.Contains(t, report.Unmeasured[0], "too many queries")
}

func TestEvaluateCountsAMeasuredTrackAsMeasured(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "1.0.0",
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{Version: "1.0.0", Outcome: regtypes.OutcomeClean}},
			"sha256:snap", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Maybe()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Empty(t, report.Unmeasured)
}

func TestANewTrackWithNoCurrentVersionIsStillCounted(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "typescript", Ecosystem: "typescript", Prefix: "5", Current: "",
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "typescript", "typescript").
		Return([]regtypes.Candidate{{
			Version:    "5.9.3",
			ReleasedAt: days(-60),
			Outcome:    regtypes.OutcomeUnreachable,
			Reason:     "the vulnerability feed refused the request: too many queries",
		}}, "sha256:snap", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Maybe()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)

	require.Len(t, report.Unmeasured, 1,
		"nothing about this package was ever checked, and the run must say so")
	require.Contains(t, report.Unmeasured[0], "typescript:typescript")
	require.Contains(t, report.Unmeasured[0], "too many queries")
}

func TestANewTrackTheFeedAnsweredAboutIsQuiet(t *testing.T) {
	h := newHarness(t)

	track := regtypes.Track{
		Package: "example.com/pkg", Ecosystem: "go", Prefix: "1", Current: "",
	}

	h.store.EXPECT().Tracks(mock.Anything).Return([]regtypes.Track{track}, nil).Once()
	h.discovery.EXPECT().Discover(mock.Anything, "go", "example.com/pkg").
		Return([]regtypes.Candidate{{
			Version:    "1.0.0",
			ReleasedAt: days(60),
			Outcome:    regtypes.OutcomeClean,
		}}, "sha256:snap", nil).Once()
	h.store.EXPECT().PutTrack(mock.Anything, mock.Anything).Return(nil).Maybe()

	report, err := h.c.Evaluate(context.Background(), now)
	require.NoError(t, err)
	require.Empty(t, report.Unmeasured)
}

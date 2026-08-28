package discoverycontroller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/controller/discoverycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/osvadaptermock"
	"github.com/alexandremahdhaoui/forge-register/internal/mocks/registryadaptermock"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

func TestDiscoverMergesVersionsWithTheirVulns(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	registries := registryadaptermock.NewMockLister(t)
	registries.EXPECT().Versions(mock.Anything, "rust", "example-crate").
		Return([]regtypes.Candidate{
			{Version: "1.0.0", ReleasedAt: at},
			{Version: "1.1.0", ReleasedAt: at},
		}, nil).Once()

	osv := osvadaptermock.NewMockQuerier(t)
	osv.EXPECT().Vulns(mock.Anything, "rust", "example-crate", []string{"1.0.0", "1.1.0"}).
		Return(map[string]regtypes.Answer{
			"1.0.0": {
				Outcome: regtypes.OutcomeFindings,
				Reason:  "1 published range(s) cover 1.0.0",
				Vulns:   []regtypes.Vuln{{ID: "RUSTSEC-1", Severity: regtypes.SeverityHigh}},
			},
			"1.1.0": {
				Outcome: regtypes.OutcomeClean,
				Reason:  "the feed carries 1 record(s) for example-crate and none of their ranges cover 1.1.0",
			},
		}, "sha256:snap", nil).Once()

	candidates, snapshot, err := discoverycontroller.New(registries, osv).
		Discover(context.Background(), "rust", "example-crate")
	require.NoError(t, err)
	require.Equal(t, "sha256:snap", snapshot)

	require.Equal(t, regtypes.Vector{High: 1}, candidates[0].Vulns)
	require.Equal(t, []string{"RUSTSEC-1"}, candidates[0].VulnIDs)
	require.Equal(t, regtypes.Vector{}, candidates[1].Vulns)

	// The outcome travels with the vector, all the way from the feed to the
	// file. A zero vector on its own is the record that claimed 56 packages
	// were clean when nothing had been asked about any of them.
	require.Equal(t, regtypes.OutcomeFindings, candidates[0].Outcome)
	require.Equal(t, regtypes.OutcomeClean, candidates[1].Outcome)
	require.Contains(t, candidates[1].Reason, "none of their ranges cover 1.1.0")
}

func TestDiscoverWrapsEitherFailure(t *testing.T) {
	boom := errors.New("boom")

	registries := registryadaptermock.NewMockLister(t)
	registries.EXPECT().Versions(mock.Anything, "rust", "x").Return(nil, boom).Once()
	osv := osvadaptermock.NewMockQuerier(t)

	_, _, err := discoverycontroller.New(registries, osv).Discover(context.Background(), "rust", "x")
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, "discovering rust:x")

	registries.EXPECT().Versions(mock.Anything, "rust", "x").
		Return([]regtypes.Candidate{{Version: "1.0.0"}}, nil).Once()
	osv.EXPECT().Vulns(mock.Anything, "rust", "x", []string{"1.0.0"}).
		Return(nil, "", boom).Once()

	_, _, err = discoverycontroller.New(registries, osv).Discover(context.Background(), "rust", "x")
	require.ErrorIs(t, err, boom)
}

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
		Return(map[string][]regtypes.Vuln{
			"1.0.0": {{ID: "RUSTSEC-1", Severity: regtypes.SeverityHigh}},
		}, "sha256:snap", nil).Once()

	candidates, snapshot, err := discoverycontroller.New(registries, osv).
		Discover(context.Background(), "rust", "example-crate")
	require.NoError(t, err)
	require.Equal(t, "sha256:snap", snapshot)

	require.Equal(t, regtypes.Vector{High: 1}, candidates[0].Vulns)
	require.Equal(t, []string{"RUSTSEC-1"}, candidates[0].VulnIDs)
	require.Equal(t, regtypes.Vector{}, candidates[1].Vulns)
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

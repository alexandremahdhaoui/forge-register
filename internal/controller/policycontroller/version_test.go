package policycontroller_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/controller/policycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// The version helpers are unexported, so their edges are pinned through the
// policy functions that use them.

func TestVersionOrderingEdges(t *testing.T) {
	clean := regtypes.Vector{}

	for _, tc := range []struct {
		name        string
		current     string
		candidate   string
		wantAdopted bool
	}{
		{"a-v-prefix-is-tolerated", "v1.2.0", "1.2.1", true},
		{"a-pre-release-sorts-below-its-release", "1.2.0", "1.2.0-rc.1", false},
		{"missing-parts-count-as-zero", "1.2", "1.2.0", false},
		{"double-digit-parts-order-numerically", "1.9.0", "1.10.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := track("1", tc.current, clean)
			v := policycontroller.EvaluateUpgrade(tr,
				[]regtypes.Candidate{candidate(tc.candidate, 30, clean)}, now, params())

			if tc.wantAdopted {
				require.Equal(t, regtypes.VerdictAdopted, v.Code)

				return
			}

			require.Equal(t, regtypes.VerdictUpToDate, v.Code)
		})
	}
}

func TestAFinerPrefixMatchesOnlyItsLine(t *testing.T) {
	clean := regtypes.Vector{}
	tr := track("1.27", "1.27.3", clean)

	v := policycontroller.EvaluateUpgrade(tr, []regtypes.Candidate{
		candidate("1.28.0", 90, clean),
		candidate("1.27.4", 90, clean),
	}, now, params())

	require.Equal(t, regtypes.VerdictAdopted, v.Code)
	require.Equal(t, "1.27.4", v.Adopted)
}

func TestSeverityFloorLevels(t *testing.T) {
	for _, tc := range []struct {
		floor   regtypes.Severity
		vector  regtypes.Vector
		exceeds bool
	}{
		{regtypes.SeverityCritical, regtypes.Vector{High: 3}, false},
		{regtypes.SeverityHigh, regtypes.Vector{High: 1}, true},
		{regtypes.SeverityMedium, regtypes.Vector{Medium: 1}, true},
		{regtypes.SeverityLow, regtypes.Vector{Low: 1}, true},
		{regtypes.SeverityLow, regtypes.Vector{}, false},
	} {
		require.Equal(t, tc.exceeds, tc.vector.Exceeds(tc.floor),
			"floor %s vector %v", tc.floor, tc.vector)
	}
}

func TestVectorStringReadsLikeTheDesignDoc(t *testing.T) {
	require.Equal(t, "(0,1,0,2)", regtypes.Vector{High: 1, Low: 2}.String())
}

func TestAnAdoptionVerdictCarriesTheDecisionTime(t *testing.T) {
	tr := track("1", "1.0.0", regtypes.Vector{})
	v := policycontroller.EvaluateUpgrade(tr,
		[]regtypes.Candidate{candidate("1.0.1", 30, regtypes.Vector{})}, now, params())
	require.Equal(t, now, v.DecidedAt)
	require.False(t, v.DecidedAt.Equal(time.Time{}))
}

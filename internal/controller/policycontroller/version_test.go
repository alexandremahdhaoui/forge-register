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

func TestPrereleasesAreNeverCandidates(t *testing.T) {
	clean := regtypes.Vector{}

	// Upgrade: a newer pre-release does not advance the track.
	tr := track("7", "7.0.0", clean)
	v := policycontroller.EvaluateUpgrade(tr, []regtypes.Candidate{
		candidate("7.1.0-dev.20260821", 30, clean),
	}, now, params())
	require.Equal(t, regtypes.VerdictUpToDate, v.Code)

	// Admission with no version: the pool holds releases only, and the
	// default track comes from released majors.
	v = policycontroller.EvaluateAdmission(regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "p", Ecosystem: "typescript", Reason: "r",
	}, []regtypes.Candidate{
		candidate("5.9.2", 90, clean),
		candidate("6.0.0-beta.1", 30, clean),
	}, now, params())
	require.Equal(t, regtypes.VerdictAdopted, v.Code)
	require.Equal(t, "5.9.2", v.Adopted)

	// An exact request may still name a pre-release: nothing is substituted.
	v = policycontroller.EvaluateAdmission(regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "p", Ecosystem: "typescript",
		Version: "6.0.0-beta.1", Reason: "r",
	}, []regtypes.Candidate{
		candidate("6.0.0-beta.1", 30, clean),
	}, now, params())
	require.Equal(t, regtypes.VerdictAdopted, v.Code)
}

func TestPrereleaseTagsOrderTheSemverWay(t *testing.T) {
	clean := regtypes.Vector{}

	// alpha.13 is newer than alpha.9: numeric identifiers compare
	// numerically, not lexically.
	tr := track("4", "4.0.0-alpha.9", clean)
	v := policycontroller.EvaluateUpgrade(tr, []regtypes.Candidate{
		candidate("4.0.0-alpha.13", 30, clean),
	}, now, params())
	// Pre-releases are not candidates at all - but the ordering itself must
	// hold for exact requests, pinned here through the comparison.
	require.Equal(t, regtypes.VerdictUpToDate, v.Code)
	require.Equal(t, -1, policycontroller.CompareVersions("4.0.0-alpha.9", "4.0.0-alpha.13"))
	require.Equal(t, 1, policycontroller.CompareVersions("4.0.0", "4.0.0-alpha.13"))
}

func TestPEP440PrereleasesAreNeverCandidates(t *testing.T) {
	clean := regtypes.Vector{}

	// Python spells pre-releases with no hyphen: 1.0.dev5, 1.0rc1. This
	// exact shape once entered an index as a release.
	tr := track("0", "0.28.1", clean)
	v := policycontroller.EvaluateUpgrade(tr, []regtypes.Candidate{
		candidate("1.0.dev5", 400, clean),
		candidate("1.0rc1", 400, clean),
	}, now, params())
	require.Equal(t, regtypes.VerdictUpToDate, v.Code)

	// Admission picks the release, not the newer .dev.
	v = policycontroller.EvaluateAdmission(regtypes.Request{
		Type: regtypes.RequestAdmission, Package: "p", Ecosystem: "python", Reason: "r",
	}, []regtypes.Candidate{
		candidate("0.28.1", 400, clean),
		candidate("1.0.dev5", 30, clean),
	}, now, params())
	require.Equal(t, regtypes.VerdictAdopted, v.Code)
	require.Equal(t, "0.28.1", v.Adopted)

	// The numeric prefix of 1.0rc1 still places it in track 1, so an exact
	// request lands where the release will.
	require.True(t, policycontroller.InPrefix("1.0rc1", "1"))
	require.Negative(t, policycontroller.CompareVersions("1.0rc1", "1.0"))
	require.Negative(t, policycontroller.CompareVersions("1.0.dev5", "1.0rc1"),
		"dev sorts below rc the pre-release way")
}

func TestVersionParsingHandlesMixedTails(t *testing.T) {
	// A hyphen tail and a PEP 440 tail in one version: both land in the
	// pre-release tag, ordered tail-first.
	require.Negative(t, policycontroller.CompareVersions("1.0rc1-x", "1.0"))
	require.Negative(t, policycontroller.CompareVersions("1.0rc1-a", "1.0rc1-b"))

	// Leading digits of a mixed segment stay numeric: 1.2rc1 is in 1.2.
	require.True(t, policycontroller.InPrefix("1.2rc1", "1.2"))
	require.False(t, policycontroller.InPrefix("1.2rc1", "1.3"))
	require.Positive(t, policycontroller.CompareVersions("1.2rc1", "1.1"))
}

func TestIsPrereleaseIsExported(t *testing.T) {
	require.True(t, policycontroller.IsPrerelease("1.0.dev5"))
	require.False(t, policycontroller.IsPrerelease("1.0.0"))
}

func TestPrereleaseIdentifierOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha.9", "1.0.0-alpha.13", -1},  // numeric ids compare numerically
		{"1.0.0-alpha.13", "1.0.0-alpha.9", 1},   // and both ways round
		{"1.0.0-1", "1.0.0-alpha", -1},           // numeric sorts before alphabetic
		{"1.0.0-alpha", "1.0.0-1", 1},            //
		{"1.0.0-alpha", "1.0.0-beta", -1},        // alphabetic ids sort lexically
		{"1.0.0-alpha", "1.0.0-alpha", 0},        // equal is equal
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},     // a shorter tag sorts first
		{"1.0.0-alpha.1", "1.0.0-alpha", 1},      //
		{"1.0.0-alpha.2", "1.0.0-alpha.2.x", -1}, // shared prefix, longer wins
	}
	for _, c := range cases {
		require.Equal(t, c.want, policycontroller.CompareVersions(c.a, c.b),
			"%s vs %s", c.a, c.b)
	}
}

func TestMajorOfEdges(t *testing.T) {
	require.Equal(t, "2", policycontroller.MajorOf("v2.1.0"))
	require.Equal(t, "", policycontroller.MajorOf("nonsense"))
}

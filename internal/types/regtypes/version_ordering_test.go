package regtypes_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Ordering is what decides whether an advisory's range covers a version, so a
// wrong answer here is a wrong security verdict.
//
// Every row was wrong before. The build-metadata and post-release rows are
// the ones that matter: they were false negatives, where a version an
// advisory names as affected read as clean.
func TestVersionOrderingDecidesAdvisories(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		why  string
	}{
		{
			"v2.0.0+incompatible", "2.0.0", 0,
			"build metadata is not part of precedence, and +incompatible is ordinary Go vocabulary",
		},
		{"2.0.0+incompatible", "2.1.0", -1, "and it must still order by the numbers"},
		{"1.0.post1", "1.0", 1, "PEP 440: a post-release comes after its release"},
		{"1.0.post1", "1.1", -1, "but not after the next one"},
		{"1.0-rc1", "1.0", -1, "a pre-release still comes before its release"},
		{"1.0-rc1", "1.0.post1", -1, "and before a post-release of the same version"},
		{"4.0.0-alpha.9", "4.0.0-alpha.13", -1, "pre-release parts compare numerically"},
		{"v0.55.0", "0.55.0", 0, "ecosystems disagree about the leading v"},
		{"1.2", "1.2.0", 0, "a missing part is zero"},
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			require.Equal(t, tc.want, regtypes.CompareVersions(tc.a, tc.b), tc.why)
			require.Equal(t, -tc.want, regtypes.CompareVersions(tc.b, tc.a), "and the reverse")
		})
	}
}

func TestAPostReleaseIsNotAPrerelease(t *testing.T) {
	require.False(t, regtypes.IsPrerelease("1.0.post1"))
	require.False(t, regtypes.IsPrerelease("v2.0.0+incompatible"),
		"reading build metadata as a pre-release made every +incompatible module unadoptable")
	require.True(t, regtypes.IsPrerelease("1.0.dev5"))
	require.True(t, regtypes.IsPrerelease("4.0.0-alpha.9"))
}

func TestOnlySomethingWithANumberIsAVersion(t *testing.T) {
	require.True(t, regtypes.IsVersion("v1.2.3"))
	require.True(t, regtypes.IsVersion("1.0.dev5"))
	require.False(t, regtypes.IsVersion("not-a-version"),
		"it sorts below everything, so it lands inside every range opening at zero")
	require.False(t, regtypes.IsVersion(""))
}

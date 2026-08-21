package policycontroller_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/controller/policycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

var now = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

func params() regtypes.Params {
	return regtypes.Params{
		QuarantineDays:       7,
		AdmissionMaxSeverity: regtypes.SeverityCritical,
		DeprecateAfterDays:   30,
		StaleAfterDays:       180,
		DeprecatedGraceDays:  30,
		MaxTracksPerPackage:  2,
	}
}

func candidate(version string, releasedDaysAgo int, vulns regtypes.Vector) regtypes.Candidate {
	return regtypes.Candidate{Version: version, ReleasedAt: days(releasedDaysAgo), Vulns: vulns}
}

func track(prefix, current string, currentVulns regtypes.Vector) regtypes.Track {
	return regtypes.Track{
		Package: "example.com/pkg", Ecosystem: "go", Prefix: prefix, Current: current,
		History: []regtypes.Entry{{Version: current, Vulns: currentVulns}},
	}
}

func TestCompareVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b regtypes.Vector
		want int
	}{
		{"equal", regtypes.Vector{}, regtypes.Vector{}, 0},
		{"a-critical-never-trades-against-lows",
			regtypes.Vector{Critical: 1}, regtypes.Vector{Low: 99}, 1},
		{"fixing-a-high-wins-despite-a-new-low",
			regtypes.Vector{Low: 1}, regtypes.Vector{High: 1}, -1},
		{"counts-compare-within-a-class",
			regtypes.Vector{Medium: 2}, regtypes.Vector{Medium: 3}, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.a.Compare(tc.b))
			require.Equal(t, -tc.want, tc.b.Compare(tc.a))
		})
	}
}

func TestVectorOfCountsUnknownAsHigh(t *testing.T) {
	v := regtypes.VectorOf([]regtypes.Vuln{
		{ID: "a", Severity: regtypes.SeverityCritical},
		{ID: "b", Severity: "moderate-ish"},
		{ID: "c", Severity: regtypes.SeverityLow},
	})
	require.Equal(t, regtypes.Vector{Critical: 1, High: 1, Low: 1}, v)
}

func TestEvaluateUpgrade(t *testing.T) {
	clean := regtypes.Vector{}
	oneLow := regtypes.Vector{Low: 1}
	oneHigh := regtypes.Vector{High: 1}

	for _, tc := range []struct {
		name        string
		track       regtypes.Track
		candidates  []regtypes.Candidate
		wantCode    string
		wantAdopted string
	}{
		{
			name:       "no-candidate-is-a-verdict-not-silence",
			track:      track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{candidate("1.1.0", 90, clean)},
			wantCode:   regtypes.VerdictUpToDate,
		},
		{
			name:  "security-upgrade-waives-quarantine",
			track: track("1", "1.2.0", oneHigh),
			candidates: []regtypes.Candidate{
				candidate("1.2.1", 0, oneLow), // released today, fixes the high, adds a low
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "1.2.1",
		},
		{
			name:  "equal-vector-waits-quarantine",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("1.2.1", 2, clean), // inside the 7-day quarantine
			},
			wantCode: regtypes.VerdictHeldQuarantined,
		},
		{
			name:  "equal-vector-adopts-after-quarantine",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("1.2.1", 10, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "1.2.1",
		},
		{
			name:  "newest-adoptable-wins",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("1.2.1", 30, clean),
				candidate("1.2.2", 10, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "1.2.2",
		},
		{
			name:  "worse-vector-held",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("1.2.1", 30, oneHigh),
			},
			wantCode: regtypes.VerdictHeldWorseVector,
		},
		{
			name:  "a-quarantined-newest-does-not-hide-a-baked-older-candidate",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("1.2.2", 1, clean),
				candidate("1.2.1", 20, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "1.2.1",
		},
		{
			name:  "another-track-does-not-leak-in",
			track: track("1", "1.2.0", clean),
			candidates: []regtypes.Candidate{
				candidate("2.0.0", 90, clean),
			},
			wantCode: regtypes.VerdictUpToDate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := policycontroller.EvaluateUpgrade(tc.track, tc.candidates, now, params())
			require.Equal(t, tc.wantCode, v.Code)
			require.Equal(t, tc.wantAdopted, v.Adopted)
			require.NotEmpty(t, v.Message, "every verdict explains itself")
			require.Equal(t, tc.track.Package, v.Package)
		})
	}
}

func TestEvaluateAdmission(t *testing.T) {
	clean := regtypes.Vector{}
	critical := regtypes.Vector{Critical: 1}

	req := func(version, trackPrefix string) regtypes.Request {
		return regtypes.Request{
			Type: regtypes.RequestAdmission, Package: "example.com/pkg", Ecosystem: "go",
			Version: version, Track: trackPrefix, Reason: "needed",
		}
	}

	for _, tc := range []struct {
		name        string
		req         regtypes.Request
		available   []regtypes.Candidate
		wantCode    string
		wantAdopted string
		wantAlts    int
	}{
		{
			name: "no-version-picks-safest-then-freshest",
			req:  req("", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 30, critical),
				candidate("2.3.9", 90, regtypes.Vector{Medium: 1}),
				candidate("2.3.5", 200, regtypes.Vector{Medium: 1}),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "2.3.9",
		},
		{
			name: "floor-violation-rejects-with-alternatives",
			req:  req("", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 30, critical),
			},
			wantCode: regtypes.VerdictDeniedOverFloor,
			wantAlts: 1,
		},
		{
			name: "all-in-quarantine-is-pending",
			req:  req("", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 1, clean),
			},
			wantCode: regtypes.VerdictPendingAdmission,
			wantAlts: 1,
		},
		{
			name: "exact-version-adopts-when-clean-and-baked",
			req:  req("2.3.9", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 30, critical),
				candidate("2.3.9", 90, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "2.3.9",
		},
		{
			name: "exact-version-with-a-critical-is-rejected-never-substituted",
			req:  req("2.4.1", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 30, critical),
				candidate("2.3.9", 90, clean),
			},
			wantCode: regtypes.VerdictDeniedOverFloor,
			wantAlts: 1,
		},
		{
			name: "exact-version-in-quarantine-rejected",
			req:  req("2.4.1", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 1, clean),
				candidate("2.3.9", 90, clean),
			},
			wantCode: regtypes.VerdictDeniedQuarantined,
			wantAlts: 1,
		},
		{
			name: "unknown-version-names-the-newest",
			req:  req("9.9.9", ""),
			available: []regtypes.Candidate{
				candidate("2.4.1", 30, clean),
			},
			wantCode: regtypes.VerdictDeniedUnknown,
		},
		{
			name:      "no-releases-at-all",
			req:       req("", ""),
			available: nil,
			wantCode:  regtypes.VerdictDeniedUnknown,
		},
		{
			name: "requested-track-narrows-the-pool",
			req:  req("", "1"),
			available: []regtypes.Candidate{
				candidate("2.0.0", 90, clean),
				candidate("1.9.0", 90, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "1.9.0",
		},
		{
			name: "default-pool-is-the-highest-major",
			req:  req("", ""),
			available: []regtypes.Candidate{
				candidate("1.9.0", 400, clean),
				candidate("2.0.0", 90, clean),
			},
			wantCode:    regtypes.VerdictAdopted,
			wantAdopted: "2.0.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := policycontroller.EvaluateAdmission(tc.req, tc.available, now, params())
			require.Equal(t, tc.wantCode, v.Code)
			require.Equal(t, tc.wantAdopted, v.Adopted)
			require.NotEmpty(t, v.Message)
			require.GreaterOrEqual(t, len(v.Alternatives), tc.wantAlts,
				"a rejection offers what to ask for instead")

			if tc.wantCode == regtypes.VerdictAdopted && tc.req.Track == "" && tc.req.Version == "" {
				require.NotEmpty(t, v.Track, "an admission lands in a track")
			}
		})
	}
}

func TestEvaluateTrackOpen(t *testing.T) {
	clean := regtypes.Vector{}

	req := regtypes.Request{
		Type: regtypes.RequestOpenTrack, Package: "example.com/pkg", Ecosystem: "go",
		Track: "1.27", Reason: "1.28 breaks the v1 config API",
	}

	maintained := []regtypes.Candidate{
		candidate("1.27.0", 400, clean),
		candidate("1.28.0", 300, clean), // successor line opened...
		candidate("1.27.9", 20, clean),  // ...and 1.27 still receives releases after it
	}

	defaultCurrent := candidate("1.28.0", 300, clean)

	for _, tc := range []struct {
		name     string
		in       policycontroller.TrackOpenInput
		wantCode string
	}{
		{
			name: "a-maintained-line-opens",
			in: policycontroller.TrackOpenInput{
				Request: req, Versions: maintained, DefaultCurrent: &defaultCurrent,
			},
			wantCode: regtypes.VerdictAdopted,
		},
		{
			name: "not-a-maintained-line-denied",
			in: policycontroller.TrackOpenInput{
				Request: req,
				Versions: []regtypes.Candidate{
					candidate("1.27.0", 400, clean),
					candidate("1.28.0", 300, clean), // nothing in 1.27 since 1.28 exists
				},
				DefaultCurrent: &defaultCurrent,
			},
			wantCode: regtypes.VerdictDeniedUnmaintained,
		},
		{
			name: "a-line-with-no-successor-is-a-pin-in-disguise",
			in: policycontroller.TrackOpenInput{
				Request: req,
				Versions: []regtypes.Candidate{
					candidate("1.27.0", 400, clean),
					candidate("1.27.9", 20, clean),
				},
			},
			wantCode: regtypes.VerdictDeniedUnmaintained,
		},
		{
			name: "security-regression-denied",
			in: policycontroller.TrackOpenInput{
				Request: req,
				Versions: []regtypes.Candidate{
					candidate("1.27.0", 400, clean),
					candidate("1.28.0", 300, clean),
					candidate("1.27.9", 20, regtypes.Vector{High: 1}),
				},
				DefaultCurrent: &defaultCurrent,
			},
			wantCode: regtypes.VerdictDeniedRegression,
		},
		{
			name: "over-budget-denied",
			in: policycontroller.TrackOpenInput{
				Request: req, Versions: maintained, DefaultCurrent: &defaultCurrent,
				NonMajorTracks: 2,
			},
			wantCode: regtypes.VerdictDeniedOverBudget,
		},
		{
			name: "no-release-in-the-prefix",
			in: policycontroller.TrackOpenInput{
				Request: req,
				Versions: []regtypes.Candidate{
					candidate("1.28.0", 300, clean),
				},
			},
			wantCode: regtypes.VerdictDeniedUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := policycontroller.EvaluateTrackOpen(tc.in, now, params())
			require.Equal(t, tc.wantCode, v.Code)
			require.NotEmpty(t, v.Message)
		})
	}
}

func TestEvaluateDeprecation(t *testing.T) {
	clean := regtypes.Vector{}

	for _, tc := range []struct {
		name       string
		in         policycontroller.DeprecationInput
		wantReason string
	}{
		{
			name: "advisory-with-no-fix-past-the-window",
			in: policycontroller.DeprecationInput{
				Track: regtypes.Track{
					Prefix: "1", Current: "1.2.0",
					Advisory: &regtypes.Advisory{
						VulnIDs: []string{"CVE-1"}, Severity: regtypes.SeverityHigh, Since: days(60),
					},
				},
			},
			wantReason: regtypes.DeprecationNoFix,
		},
		{
			name: "a-fresh-advisory-does-not-deprecate-yet",
			in: policycontroller.DeprecationInput{
				Track: regtypes.Track{
					Prefix: "1", Current: "1.2.0",
					Advisory: &regtypes.Advisory{
						VulnIDs: []string{"CVE-1"}, Severity: regtypes.SeverityHigh, Since: days(5),
					},
				},
			},
		},
		{
			name: "stale-past-a-successor",
			in: policycontroller.DeprecationInput{
				Track:               track("1.27", "1.27.9", clean),
				HasSuccessor:        true,
				LastReleaseInPrefix: days(200),
			},
			wantReason: regtypes.DeprecationStale,
		},
		{
			name: "stale-without-a-successor-stays",
			in: policycontroller.DeprecationInput{
				Track:               track("1", "1.2.0", clean),
				LastReleaseInPrefix: days(400),
			},
		},
		{
			name: "already-deprecated-is-stable",
			in: policycontroller.DeprecationInput{
				Track: regtypes.Track{
					Prefix: "1.27", Current: "1.27.9",
					Deprecated: &regtypes.Deprecation{Reason: regtypes.DeprecationStale, Since: days(10)},
				},
			},
			wantReason: regtypes.DeprecationStale,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := policycontroller.EvaluateDeprecation(tc.in, now, params())
			if tc.wantReason == "" {
				require.Nil(t, d)

				return
			}

			require.NotNil(t, d)
			require.Equal(t, tc.wantReason, d.Reason)
		})
	}
}

func TestAFreshDisclosureOnCurrentOverridesTheHistory(t *testing.T) {
	// The history recorded a clean adoption; the fresh snapshot says current
	// now carries a critical, and a clean release exists: security upgrade.
	tr := track("1", "1.1.0", regtypes.Vector{})

	v := policycontroller.EvaluateUpgrade(tr, []regtypes.Candidate{
		candidate("1.1.0", 60, regtypes.Vector{Critical: 1}),
		candidate("1.2.1", 0, regtypes.Vector{}),
	}, now, params())

	require.Equal(t, regtypes.VerdictAdopted, v.Code)
	require.Equal(t, "1.2.1", v.Adopted)
	require.Contains(t, v.Message, "security upgrade")
}

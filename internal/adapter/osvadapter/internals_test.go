package osvadapter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Small rules that no captured record happens to exercise, each of which
// could be deleted with every other test still green.

// A record covering the same package twice must count once. The vector it
// feeds is what the severity gate reads, so a double count promotes a finding
// into a class the feed never assigned it.
func TestARecordCoveringOnePackageTwiceCountsOnce(t *testing.T) {
	r := record{ID: "GHSA-twice", Affected: []affected{
		{Name: "p", Ecosystem: "Go", Ranges: []versionRange{{
			Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}},
		}}},
		{Name: "p", Ecosystem: "Go", Ranges: []versionRange{{
			Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "3.0.0"}},
		}}},
	}}

	got := (&HTTP{}).match(t.Context(), []record{r}, "Go", "p", "1.0.0")
	require.Len(t, got, 1)
	require.Equal(t, regtypes.Vector{High: 1}, regtypes.VectorOf(got))
}

// The feed can name the same id twice in one package answer. Reading it twice
// costs a fetch and double-counts the finding.
func TestARepeatedIDIsReadOnce(t *testing.T) {
	var all batchResult

	all.Vulns = append(all.Vulns,
		struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}{ID: "GHSA-1"},
		struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}{ID: "GHSA-1"})

	h := &HTTP{records: map[string]record{"GHSA-1": {ID: "GHSA-1"}}}

	got, err := h.recordsOf(t.Context(), all)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// Findings come back in a stable order. A verdict that reorders between runs
// is a diff nobody can read.
func TestFindingsAreOrdered(t *testing.T) {
	mk := func(id string) record {
		return record{ID: id, Affected: []affected{{
			Name: "p", Ecosystem: "Go",
			Ranges: []versionRange{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
		}}}
	}

	got := (&HTTP{}).match(t.Context(), []record{mk("GHSA-z"), mk("GHSA-a"), mk("GHSA-m")},
		"Go", "p", "1.0.0")

	require.Equal(t, []string{"GHSA-a", "GHSA-m", "GHSA-z"},
		[]string{got[0].ID, got[1].ID, got[2].ID})
}

// OSV writes distro ecosystems with a suffix: "Debian:11", "Alpine:v3.18".
// The part before the colon is the ecosystem, and an exact comparison drops
// every one of them.
func TestAnEcosystemSuffixIsNotPartOfTheEcosystem(t *testing.T) {
	require.Equal(t, "Debian", baseEcosystem("Debian:11"))
	require.Equal(t, "Alpine", baseEcosystem("Alpine:v3.18"))
	require.Equal(t, "Go", baseEcosystem("Go"))

	r := record{ID: "DEBIAN-1", Affected: []affected{{
		Name: "linux", Ecosystem: "Debian:11",
		Ranges: []versionRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}}}},
	}}}

	require.Len(t, (&HTTP{}).match(t.Context(), []record{r}, "Debian", "linux", "1.0"), 1)
}

// An import entry with no path is not an import scope. Carrying the empty
// string would read as a package everything imports.
func TestAnEmptyImportPathIsNotAScope(t *testing.T) {
	v := vulnOf(record{ID: "GO-1"}, affected{Imports: []string{"", "a/b", ""}}, "why")
	require.Equal(t, []string{"a/b"}, v.AffectedImports)
}

// The snapshot digest is what proves which answer a decision read, so it must
// not change with the order the feed happened to reply in.
func TestTheSnapshotDigestIsOrderIndependent(t *testing.T) {
	a := digestOf([]string{"1.0.0 queried", "1.0.0 GO-1 high"})
	b := digestOf([]string{"1.0.0 GO-1 high", "1.0.0 queried"})
	require.Equal(t, a, b)

	require.NotEqual(t, a, digestOf(nil))
	require.Equal(t, "sha256:e3b0c44298fc1c14", digestOf(nil),
		"an empty snapshot is the sha256 of nothing, which is why outcome is "+
			"stored beside it rather than inferred from it")
}

// CVSS v3, at the band edges and on the metrics most easily dropped.
func TestCVSSScoringMatchesTheSpecification(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   regtypes.Severity
		why    string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", regtypes.SeverityCritical, "9.8"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", regtypes.SeverityCritical,
			"10.0: the scope multiplier is what takes it there"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", regtypes.SeverityMedium,
			"6.4 under changed scope, where the privileges table differs"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", regtypes.SeverityMedium, "5.4"},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", regtypes.SeverityLow, "1.8"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", regtypes.SeverityLow,
			"no impact at all scores zero"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", regtypes.SeverityHigh, "7.5"},

		// The three below sit on a band edge and each isolates one rule.
		// Every one of them was scored a whole band low before, and no
		// vector in the captured set is close enough to notice.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", regtypes.SeverityCritical,
			"9.3 with the scope multiplier, 8.7 without it"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L", regtypes.SeverityCritical,
			"9.1 with the changed-scope privileges table, 8.8 with the unchanged one"},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L", regtypes.SeverityCritical,
			"9.0 rounding up as CVSS requires, 8.9 rounding to nearest"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			got, ok := severityOfVector("CVSS_V3", tc.vector)
			require.True(t, ok)
			require.Equal(t, tc.want, got)
		})
	}

	_, ok := severityOfVector("CVSS_V4",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	require.False(t, ok,
		"v4's base score is a lookup table, not a formula; inventing one is worse "+
			"than admitting we have none")

	_, ok = severityOfVector("CVSS_V3", "nonsense")
	require.False(t, ok)
}

// Every word a database publishes, including the one spelled two ways.
func TestEveryPublishedSeverityWordIsRead(t *testing.T) {
	for word, want := range map[string]regtypes.Severity{
		"CRITICAL": regtypes.SeverityCritical,
		"HIGH":     regtypes.SeverityHigh,
		"MODERATE": regtypes.SeverityMedium,
		"MEDIUM":   regtypes.SeverityMedium,
		"LOW":      regtypes.SeverityLow,
		"":         "",
		"unusual":  "",
	} {
		require.Equal(t, want, severityOfWord(word), "word %q", word)
	}
}

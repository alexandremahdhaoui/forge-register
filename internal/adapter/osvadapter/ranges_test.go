package osvadapter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The range walk, against the OSV specification rather than against captured
// data.
//
// None of the 267 captured records uses `limit`, and every one of them
// happens to list its events already sorted - so no fixture can reach these
// paths, and both were wrong. The cases below come from the specification's
// own reference algorithm. They are stated, not captured, and say so.
func TestTheRangeWalkFollowsTheSpecification(t *testing.T) {
	ev := func(kind, version string) rangeEvent {
		switch kind {
		case "introduced":
			return rangeEvent{Introduced: version}
		case "fixed":
			return rangeEvent{Fixed: version}
		case "last":
			return rangeEvent{LastAffected: version}
		default:
			return rangeEvent{Limit: version}
		}
	}

	block := func(events ...rangeEvent) affected {
		return affected{
			Name: "p", Ecosystem: "Go",
			Ranges: []versionRange{{Type: "SEMVER", Events: events}},
		}
	}

	for _, tc := range []struct {
		name    string
		a       affected
		version string
		want    bool
		why     string
	}{
		{
			name:    "events out of published order still describe the same range",
			a:       block(ev("fixed", "1.0.0"), ev("introduced", "0")),
			version: "5.0.0", want: false,
			why: "OSV recommends sorting but does not require it, and its reference " +
				"algorithm sorts. Walking published order reported every version " +
				"of the package as affected, forever.",
		},
		{
			name:    "and the version the unsorted range really covers",
			a:       block(ev("fixed", "1.0.0"), ev("introduced", "0")),
			version: "0.5.0", want: true,
		},
		{
			name:    "a star limit is infinity, not a closed door",
			a:       block(ev("introduced", "0"), ev("limit", "*")),
			version: "1.2.3", want: true,
			why: "treating the limit as a sequential close made * cancel the whole " +
				"range, which is a false negative on every version",
		},
		{
			name:    "a version below any one limit is inside",
			a:       block(ev("introduced", "0"), ev("limit", "2.0.0"), ev("limit", "5.0.0")),
			version: "3.0.0", want: true,
			why: "limits are a separate test, so a second higher limit widens the " +
				"range rather than shrinking it",
		},
		{
			name:    "a version above every limit is outside",
			a:       block(ev("introduced", "0"), ev("limit", "2.0.0")),
			version: "3.0.0", want: false,
		},
		{
			name: "two windows in one range",
			a: block(ev("introduced", "1.0.0"), ev("fixed", "1.2.0"),
				ev("introduced", "2.0.0"), ev("fixed", "2.1.0")),
			version: "1.5.0", want: false,
			why: "1.5.0 sits in the gap between the two windows",
		},
		{
			name: "and the second window itself",
			a: block(ev("introduced", "1.0.0"), ev("fixed", "1.2.0"),
				ev("introduced", "2.0.0"), ev("fixed", "2.1.0")),
			version: "2.0.5", want: true,
		},
		{
			name:    "the fixed version itself is not affected",
			a:       block(ev("introduced", "0"), ev("fixed", "1.2.0")),
			version: "1.2.0", want: false,
		},
		{
			name:    "the last affected version is affected",
			a:       block(ev("introduced", "0"), ev("last", "1.2.0")),
			version: "1.2.0", want: true,
			why: "which is exactly why last_affected must never be read as a fix",
		},
		{
			name:    "one patch above the last affected version is not",
			a:       block(ev("introduced", "0"), ev("last", "1.2.0")),
			version: "1.2.1", want: false,
		},
		{
			name: "a GIT range answers nothing about a semver",
			a: affected{Name: "p", Ecosystem: "Go", Ranges: []versionRange{{
				Type:   "GIT",
				Events: []rangeEvent{ev("introduced", "0")},
			}}},
			version: "1.0.0", want: false,
			why: "comparing a version against a commit hash is meaningless",
		},
		{
			name:    "an explicit versions list is an exact membership test",
			a:       affected{Name: "p", Ecosystem: "Go", Versions: []string{"1.0.0", "1.0.2"}},
			version: "1.0.1", want: false,
		},
		{
			name:    "and matches whatever the ecosystem writes for the same version",
			a:       affected{Name: "p", Ecosystem: "Go", Versions: []string{"v1.0.0"}},
			version: "1.0.0", want: true,
		},
		{
			name:    "build metadata does not move a version out of its range",
			a:       block(ev("introduced", "2.0.0"), ev("fixed", "2.1.0")),
			version: "v2.0.0+incompatible", want: true,
			why: "semver ignores build metadata for precedence; reading it as a " +
				"pre-release sorted the module below the version that introduced " +
				"the advisory, and a real finding read as clean",
		},
		{
			name:    "a post-release stays inside the range its release is in",
			a:       block(ev("introduced", "1.0"), ev("fixed", "2.0")),
			version: "1.0.post1", want: true,
			why: "PEP 440 puts a post-release after its release, not before it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := coversVersion(tc.a, tc.version)
			require.Equal(t, tc.want, got, tc.why)

			if got {
				require.NotEmpty(t, why, "a match must say which range covered us")
			}
		})
	}
}

package osvadapter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
		{
			name:    "introduced 0 covers a Go pseudo-version",
			a:       block(ev("introduced", "0"), ev("fixed", "0.17.0")),
			version: "v0.0.0-20200220183623-bac4c82f6975", want: true,
			why: "\"0\" is the beginning of time and not a version to compare " +
				"against: a pseudo-version sorts below it, so without the special " +
				"case every introduced-0 advisory - the commonest shape there is - " +
				"stopped covering the commonest Go version format, silently",
		},
		{
			name:    "and it still ends where the fix lands",
			a:       block(ev("introduced", "0"), ev("fixed", "0.17.0")),
			version: "v0.18.0", want: false,
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

// The table above builds events in Go, so it says nothing about the JSON
// tags that put them there. A renamed tag left every event empty and the
// walk answered "not covered" for everything - a green suite and a silent
// false negative on every advisory. This drives the real decode.
func TestTheRangeWalkReadsTheWireShape(t *testing.T) {
	const raw = `{
	  "id": "X-1",
	  "affected": [{
	    "package": {"name": "p", "ecosystem": "Go"},
	    "ranges": [
	      {"type": "SEMVER",
	       "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]},
	      {"type": "SEMVER",
	       "events": [{"introduced": "3.0.0"}, {"limit": "4.0.0"}]}
	    ],
	    "versions": ["1.9.9"],
	    "ecosystem_specific": {"imports": [{"path": "p/q"}]}
	  }]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, raw)
	}))
	t.Cleanup(srv.Close)

	h := New(nil, srv.URL)

	rec, err := h.fetchRecord(context.Background(), "X-1")
	require.NoError(t, err)
	require.Len(t, rec.Affected, 1)

	a := rec.Affected[0]
	require.Equal(t, "p", a.Name)
	require.Equal(t, "Go", a.Ecosystem)
	require.Equal(t, []string{"p/q"}, a.Imports)

	for _, tc := range []struct {
		version string
		want    bool
		why     string
	}{
		{"1.2.0", true, "inside the range and below the limit"},
		{"1.6.0", false, "at or past the fix"},
		// The limit is the specification's pre-test: at or above it the
		// whole range is skipped before the walk runs. No captured record
		// uses it, so losing this tag made every limited range unlimited
		// and no fixture could see it. The second range carries no fix, so
		// the limit is the only thing that can exclude 5.0.0 - a case where
		// a fix would also exclude it proves nothing about the limit.
		{"3.5.0", true, "inside the second range and below its limit"},
		{"5.0.0", false, "at or above the limit, so that range does not apply"},
		// An explicit version list is its own statement and does not need
		// the events to agree with it.
		{"1.9.9", true, "named in versions[]"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			got, _ := coversVersion(a, tc.version)
			require.Equal(t, tc.want, got, tc.why)
		})
	}
}

package policycontroller

import "github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"

// Version ordering lives in regtypes because the OSV adapter needs it too:
// deciding whether a version falls inside an advisory's range is the same
// comparison, and an adapter must never import a controller. These are the
// policy layer's names for it, so one implementation serves both.
var (
	// CompareVersions orders versions numerically, part by part.
	CompareVersions = regtypes.CompareVersions
	// InPrefix reports whether a version belongs to a track prefix.
	InPrefix = regtypes.InPrefix
	// IsPrerelease reports whether a version carries a pre-release tail.
	IsPrerelease = regtypes.IsPrerelease
	// MajorOf names the track a version belongs to.
	MajorOf = regtypes.MajorOf
)

// isPrerelease is the unexported spelling this package reads.
func isPrerelease(version string) bool { return regtypes.IsPrerelease(version) }

// Package regtypes holds the register's internal model. Wire types generated
// from forge-register-spec are mapped to these at each engine's boundary, so
// a schema change is a compile error rather than a silent misread.
package regtypes

import (
	"strconv"
	"time"
)

// Severity orders vulnerability classes. Unknown severities are counted as
// high before they reach a Vector, so the type carries only the four classes.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Vector counts known, unfixed vulnerabilities by severity. Vectors compare
// lexicographically from critical down, so a critical never trades against
// any number of lows.
type Vector struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Compare orders vectors lexicographically from critical down. Negative means
// v is safer than o.
func (v Vector) Compare(o Vector) int {
	pairs := [4][2]int{
		{v.Critical, o.Critical},
		{v.High, o.High},
		{v.Medium, o.Medium},
		{v.Low, o.Low},
	}

	for _, p := range pairs {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}

			return 1
		}
	}

	return 0
}

// Exceeds reports whether the vector carries anything at or above the floor
// severity. A floor of "critical" admits everything below a critical.
func (v Vector) Exceeds(floor Severity) bool {
	switch floor {
	case SeverityCritical:
		return v.Critical > 0
	case SeverityHigh:
		return v.Critical > 0 || v.High > 0
	case SeverityMedium:
		return v.Critical > 0 || v.High > 0 || v.Medium > 0
	case SeverityLow:
		return v.Critical > 0 || v.High > 0 || v.Medium > 0 || v.Low > 0
	}

	return false
}

// String renders the vector the way the design doc talks about it.
func (v Vector) String() string {
	return "(" + strconv.Itoa(v.Critical) + "," + strconv.Itoa(v.High) + "," +
		strconv.Itoa(v.Medium) + "," + strconv.Itoa(v.Low) + ")"
}

// Vuln is one known vulnerability affecting one version.
type Vuln struct {
	ID       string
	Severity Severity

	// Introduced and FixedIn are the range events OSV publishes, unioned
	// across every affected block of the record. An empty FixedIn means the
	// feed names no fixed version - which is a fact worth reading rather
	// than assuming, because "no fix upstream" was asserted for a year by
	// code that never looked.
	Introduced []string
	FixedIn    []string

	// AffectedImports are the import paths the advisory is scoped to, where
	// the ecosystem publishes them (largely a Go convention). Empty means
	// the feed gave no scope, NOT that everything is affected - the
	// difference decides whether a consumer can clear an advisory on the
	// merits, so the two must never collapse into one.
	AffectedImports []string
}

// VectorOf folds vulnerabilities into a vector. An unrecognised severity
// counts as high: the safe default for a feed that could not classify.
func VectorOf(vulns []Vuln) Vector {
	var v Vector

	for _, vuln := range vulns {
		switch vuln.Severity {
		case SeverityCritical:
			v.Critical++
		case SeverityMedium:
			v.Medium++
		case SeverityLow:
			v.Low++
		default:
			v.High++
		}
	}

	return v
}

// Candidate is one upstream version under consideration.
type Candidate struct {
	Version    string
	ReleasedAt time.Time
	Vulns      Vector
	VulnIDs    []string
}

// Entry is one adopted version in a track's history.
type Entry struct {
	Version     string
	ReleasedAt  time.Time
	AdoptedAt   time.Time
	Vulns       Vector
	Source      string
	Provenance  string
	OSVSnapshot string
}

// Advisory marks a current version carrying a vulnerability with no fixed
// version upstream. An advisory pierces every pin.
type Advisory struct {
	VulnIDs  []string
	Severity Severity
	Since    time.Time
}

// Deprecation is set by policy, never by hand.
type Deprecation struct {
	Reason string
	Since  time.Time
}

const (
	DeprecationNoFix = "no-fix"
	DeprecationStale = "stale"
)

// Track is a maintained line of one package: one current version, named by a
// semver prefix.
type Track struct {
	Package    string
	Ecosystem  string
	Prefix     string
	Current    string
	UpdatedAt  time.Time
	History    []Entry
	Advisory   *Advisory
	Deprecated *Deprecation
	// QuietSince is upstream's last release into the track, set by policy
	// once the track has been quiet past the stale window with no
	// successor line to deprecate toward. The track stays current; the
	// mark clears when upstream releases again or a successor appears.
	QuietSince *time.Time
}

// Request is the only door into the register.
type Request struct {
	Type      string
	Package   string
	Ecosystem string
	Track     string
	Version   string
	Requester string
	Reason    string
	CreatedAt time.Time
}

const (
	RequestAdmission = "admission"
	RequestUpgrade   = "upgrade"
	RequestOpenTrack = "open-track"
)

// Alternative is a version a denial offers instead.
type Alternative struct {
	Version    string
	ReleasedAt time.Time
	Vulns      Vector
}

// Verdict is every decision the register takes, written with its inputs.
type Verdict struct {
	Code         string
	Package      string
	Ecosystem    string
	Track        string
	Requested    string
	Adopted      string
	Alternatives []Alternative
	OSVSnapshot  string
	Message      string
	DecidedAt    time.Time
}

const (
	VerdictAdopted            = "adopted"
	VerdictUpToDate           = "up-to-date"
	VerdictHeldWorseVector    = "held-worse-vector"
	VerdictHeldQuarantined    = "held-quarantined"
	VerdictHeldCanaryRed      = "held-canary-red"
	VerdictPendingAdmission   = "pending-admission"
	VerdictDeniedOverFloor    = "denied-over-floor"
	VerdictDeniedQuarantined  = "denied-quarantined"
	VerdictDeniedUnknown      = "denied-unknown-version"
	VerdictDeniedUnmaintained = "denied-not-a-maintained-line"
	VerdictDeniedRegression   = "denied-security-regression"
	VerdictDeniedOverBudget   = "denied-over-budget"
)

// Params are the register-level policy knobs. A consumer can read them and
// can never set them.
type Params struct {
	QuarantineDays       int
	AdmissionMaxSeverity Severity
	DeprecateAfterDays   int
	StaleAfterDays       int
	DeprecatedGraceDays  int
	MaxTracksPerPackage  int
}

package osvadapter

import (
	"math"
	"strings"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// CVSS v3 base metric weights, from the specification. Privileges Required
// is the one metric whose weight depends on Scope, which is why it is two
// tables rather than one.
var (
	cvss3AV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvss3AC = map[string]float64{"L": 0.77, "H": 0.44}
	cvss3UI = map[string]float64{"N": 0.85, "R": 0.62}
	cvss3IM = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	cvss3PRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvss3PRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// severityOfVector reads a CVSS vector string and answers the class its base
// score falls in. Only v3 is computed: v4's base score is a 270-entry lookup
// table rather than a formula, and inventing a number for it would be worse
// than admitting we do not have one, so a v4-only record falls through to
// the alias chain instead.
//
// The second return says whether a score was produced at all.
func severityOfVector(kind, vector string) (regtypes.Severity, bool) {
	if kind != "CVSS_V3" {
		return "", false
	}

	m := map[string]string{}

	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}

	scopeChanged := m["S"] == "C"

	pr := cvss3PRUnchanged
	if scopeChanged {
		pr = cvss3PRChanged
	}

	av, okAV := cvss3AV[m["AV"]]
	ac, okAC := cvss3AC[m["AC"]]
	prv, okPR := pr[m["PR"]]
	ui, okUI := cvss3UI[m["UI"]]
	c, okC := cvss3IM[m["C"]]
	i, okI := cvss3IM[m["I"]]
	a, okA := cvss3IM[m["A"]]

	if !okAV || !okAC || !okPR || !okUI || !okC || !okI || !okA {
		return "", false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return regtypes.SeverityLow, true
	}

	exploitability := 8.22 * av * ac * prv * ui

	score := impact + exploitability
	if scopeChanged {
		score *= 1.08
	}

	return bandOf(roundUp(math.Min(score, 10))), true
}

// roundUp is CVSS's own rounding: up to one decimal, never down. Plain
// rounding puts a 6.95 in the wrong band.
func roundUp(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// bandOf is the qualitative scale from the CVSS specification.
func bandOf(score float64) regtypes.Severity {
	switch {
	case score >= 9.0:
		return regtypes.SeverityCritical
	case score >= 7.0:
		return regtypes.SeverityHigh
	case score >= 4.0:
		return regtypes.SeverityMedium
	default:
		return regtypes.SeverityLow
	}
}

// severityOfWord maps the word a database publishes to ours. GitHub-sourced
// records carry one; the Go, PyPI and RustSec databases do not.
func severityOfWord(word string) regtypes.Severity {
	switch strings.ToUpper(strings.TrimSpace(word)) {
	case "CRITICAL":
		return regtypes.SeverityCritical
	case "HIGH":
		return regtypes.SeverityHigh
	case "MODERATE", "MEDIUM":
		return regtypes.SeverityMedium
	case "LOW":
		return regtypes.SeverityLow
	}

	return ""
}

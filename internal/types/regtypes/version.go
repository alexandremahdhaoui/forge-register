package regtypes

import (
	"strconv"
	"strings"
)

// parseVersion splits a version into numeric parts and a pre-release tail. A
// leading v is tolerated because ecosystems disagree about it. PEP 440 spells
// pre-releases with no hyphen (1.0.dev5, 1.0rc1), so any non-numeric segment
// is a pre-release tail too - this is what once let a .dev version into an
// index as a release.
func parseVersion(s string) ([]int, string) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")

	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}

	raw := strings.Split(s, ".")
	parts := make([]int, 0, len(raw))

	for i, r := range raw {
		n, err := strconv.Atoi(r)
		if err == nil {
			parts = append(parts, n)

			continue
		}

		// Leading digits stay a numeric part (1.0rc1 is in track 1.0);
		// everything from the first non-digit joins the pre-release tail.
		digits := len(r) - len(strings.TrimLeft(r, "0123456789"))
		if digits > 0 {
			n, _ := strconv.Atoi(r[:digits])
			parts = append(parts, n)
		}

		tail := strings.Join(append([]string{r[digits:]}, raw[i+1:]...), ".")
		if pre == "" {
			pre = tail
		} else {
			pre = tail + "." + pre
		}

		break
	}

	return parts, pre
}

// CompareVersions orders versions numerically part by part. Missing parts
// count as zero, and a pre-release sorts below its release.
func CompareVersions(a, b string) int {
	ap, apre := parseVersion(a)
	bp, bpre := parseVersion(b)

	for i := 0; i < len(ap) || i < len(bp); i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}

		if i < len(bp) {
			bv = bp[i]
		}

		if av != bv {
			if av < bv {
				return -1
			}

			return 1
		}
	}

	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}

	return comparePrerelease(apre, bpre)
}

// comparePrerelease orders pre-release tags the semver way: dot-separated
// identifiers, numeric ones numerically, and a shorter tag sorts first.
func comparePrerelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")

	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])

		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}

				return 1
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if as[i] != bs[i] {
				if as[i] < bs[i] {
					return -1
				}

				return 1
			}
		}
	}

	switch {
	case len(as) == len(bs):
		return 0
	case len(as) < len(bs):
		return -1
	}

	return 1
}

// InPrefix reports whether a version belongs to a track prefix: the prefix's
// numeric parts must equal the version's leading parts.
func InPrefix(version, prefix string) bool {
	vp, _ := parseVersion(version)
	pp, _ := parseVersion(prefix)

	if len(pp) == 0 || len(vp) < len(pp) {
		return false
	}

	for i, p := range pp {
		if vp[i] != p {
			return false
		}
	}

	return true
}

// isPrerelease reports whether a version carries a pre-release tag. A
// register catalogs releases: pre-releases are never candidates unless a
// request names one exactly.
func isPrerelease(version string) bool {
	_, pre := parseVersion(version)

	return pre != ""
}

// IsPrerelease is isPrerelease for callers outside the package: the register
// catalogs releases, and a successor line must hold at least one.
func IsPrerelease(version string) bool {
	return isPrerelease(version)
}

// MajorOf names the major-level track a version belongs to.
func MajorOf(version string) string {
	vp, _ := parseVersion(version)
	if len(vp) == 0 {
		return ""
	}

	return strconv.Itoa(vp[0])
}

// IsVersion reports whether a string is a version at all: it has at least one
// numeric part. "not-a-version" has none, and comparing it sorts it below
// everything, which silently places it inside every range that opens at zero.
// The OSV API has exactly this bug - it answered 37 records for that string
// when the truth was 36 - so the check exists to avoid reproducing it here.
func IsVersion(s string) bool {
	parts, _ := parseVersion(s)

	return len(parts) > 0
}

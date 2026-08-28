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

	// Build metadata is not part of precedence. Semver says so outright, and
	// the OSV schema warns that event versions may have it stripped, so
	// "2.0.0+incompatible" and "2.0.0" have to compare equal. Treating the
	// metadata as a pre-release tail sorted the module BELOW the version an
	// advisory names as introducing it, and a real finding read as clean.
	// +incompatible is ordinary Go vocabulary, straight off the proxy.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}

	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
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

	apost, bpost := isPostRelease(apre), isPostRelease(bpre)

	switch {
	case apre == bpre:
		return 0
	case apre == "":
		// A bare release outranks a pre-release and is outranked by a post.
		if bpost {
			return -1
		}

		return 1
	case bpre == "":
		if apost {
			return 1
		}

		return -1
	case apost != bpost:
		// A post-release outranks a pre-release of the same version.
		if apost {
			return 1
		}

		return -1
	}

	return comparePrerelease(apre, bpre)
}

// comparePrerelease orders pre-release tags the semver way: dot-separated
// identifiers, numeric ones numerically, and a shorter tag sorts first.
// isPostRelease reports a PEP 440 post-release or revision tail. These sort
// ABOVE their release: 1.0.post1 comes after 1.0, where a pre-release comes
// before it. Reading one as a pre-release put it below the version an
// advisory introduced at, so the finding read as clean.
func isPostRelease(tail string) bool {
	t := strings.ToLower(strings.TrimLeft(tail, ".-_"))

	if strings.HasPrefix(t, "post") || strings.HasPrefix(t, "rev") {
		return true
	}

	// PEP 440 also spells a post-release ".r1". A bare "r" prefix is too
	// greedy on its own - it swallows "rc1", which is a release candidate
	// and sorts the other way - so the digit is required.
	if len(t) > 1 && t[0] == 'r' && t[1] >= '0' && t[1] <= '9' {
		return true
	}

	return false
}

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

	// A post-release is not a pre-release. Reading "1.0.post1" as one meant
	// policy never adopted it, and the same mistake put +incompatible Go
	// modules permanently out of reach.
	return pre != "" && !isPostRelease(pre)
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

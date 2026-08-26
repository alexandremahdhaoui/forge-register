// Package policycontroller is the whole algorithm and nothing else: no I/O,
// no clock of its own, every input handed in and every decision returned as a
// verdict. If a rule cannot be written as a table test, it does not belong
// here.
package policycontroller

import (
	"fmt"
	"sort"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

const day = 24 * time.Hour

// EvaluateUpgrade decides whether a track advances, per the design: a
// strictly safer candidate adopts immediately, an equally safe one adopts
// after quarantine, a worse one is held. The newest adoptable candidate wins.
// Not upgrading is never silent.
func EvaluateUpgrade(track regtypes.Track, candidates []regtypes.Candidate, now time.Time, p regtypes.Params) regtypes.Verdict {
	verdict := regtypes.Verdict{
		Package:   track.Package,
		Ecosystem: track.Ecosystem,
		Track:     track.Prefix,
		DecidedAt: now,
	}

	// The history records what current's vulnerabilities were at adoption;
	// the fresh snapshot says what they are now. A disclosure on the current
	// version must move this comparison, so fresh wins when present.
	current := currentVector(track)

	for _, c := range candidates {
		if c.Version == track.Current {
			current = c.Vulns

			break
		}
	}

	// Internal versions enter by proof, and their dev labels ARE their
	// version format - filtering prereleases would filter the whole track.
	// Everywhere else a prerelease never upgrades a track on its own.
	admitPrereleases := track.Ecosystem == "internal"

	newer := make([]regtypes.Candidate, 0, len(candidates))
	for _, c := range candidates {
		if isPrerelease(c.Version) && !admitPrereleases {
			continue
		}

		if InPrefix(c.Version, track.Prefix) && CompareVersions(c.Version, track.Current) > 0 {
			newer = append(newer, c)
		}
	}

	if len(newer) == 0 {
		verdict.Code = regtypes.VerdictUpToDate
		verdict.Message = fmt.Sprintf("%s is the newest release in track %s", track.Current, track.Prefix)

		return verdict
	}

	sort.Slice(newer, func(i, j int) bool {
		return CompareVersions(newer[i].Version, newer[j].Version) > 0
	})

	var quarantined, worse *regtypes.Candidate

	for i := range newer {
		c := newer[i]

		switch c.Vulns.Compare(current) {
		case -1:
			verdict.Code = regtypes.VerdictAdopted
			verdict.Adopted = c.Version
			verdict.Message = fmt.Sprintf(
				"security upgrade: %s (%v) is strictly safer than %s (%v), quarantine waived",
				c.Version, c.Vulns, track.Current, current)

			return verdict
		case 0:
			if age(c, now) >= quarantine(p) {
				verdict.Code = regtypes.VerdictAdopted
				verdict.Adopted = c.Version
				verdict.Message = fmt.Sprintf(
					"%s is out of quarantine and no less safe than %s", c.Version, track.Current)

				return verdict
			}

			if quarantined == nil {
				quarantined = &newer[i]
			}
		case 1:
			if worse == nil {
				worse = &newer[i]
			}
		}
	}

	if quarantined != nil {
		verdict.Code = regtypes.VerdictHeldQuarantined
		verdict.Message = fmt.Sprintf(
			"%s waits out its quarantine until %s",
			quarantined.Version, quarantined.ReleasedAt.Add(quarantine(p)).Format(time.RFC3339))
		verdict.Alternatives = alternativesOf(*quarantined)

		return verdict
	}

	verdict.Code = regtypes.VerdictHeldWorseVector
	verdict.Message = fmt.Sprintf(
		"%s (%v) is less safe than %s (%v); staying", worse.Version, worse.Vulns, track.Current, current)
	verdict.Alternatives = alternativesOf(*worse)

	return verdict
}

// EvaluateAdmission decides what version an admission or upgrade request
// gets. It never substitutes a version the requester did not ask for: a
// violation is a structured rejection listing the alternatives, and choosing
// to live with one is the requester's next, explicit request.
func EvaluateAdmission(req regtypes.Request, available []regtypes.Candidate, now time.Time, p regtypes.Params) regtypes.Verdict {
	verdict := regtypes.Verdict{
		Package:   req.Package,
		Ecosystem: req.Ecosystem,
		Track:     req.Track,
		Requested: req.Version,
		DecidedAt: now,
	}

	if len(available) == 0 {
		verdict.Code = regtypes.VerdictDeniedUnknown
		verdict.Message = "upstream has no releases"

		return verdict
	}

	if req.Version != "" {
		return evaluateExact(verdict, req, available, now, p)
	}

	pool := poolFor(req, available)
	if len(pool) == 0 {
		verdict.Code = regtypes.VerdictDeniedUnknown
		verdict.Message = fmt.Sprintf("upstream has no release in track %s; newest is %s",
			req.Track, newest(available).Version)

		return verdict
	}

	sortForAdmission(pool)

	for _, c := range pool {
		if c.Vulns.Exceeds(p.AdmissionMaxSeverity) {
			continue
		}

		if age(c, now) >= quarantine(p) {
			verdict.Code = regtypes.VerdictAdopted
			verdict.Adopted = c.Version
			verdict.Track = trackFor(req, c)
			verdict.Message = fmt.Sprintf("admitted %s (%v)", c.Version, c.Vulns)

			return verdict
		}
	}

	if passing := firstPassing(pool, p); passing != nil {
		verdict.Code = regtypes.VerdictPendingAdmission
		verdict.Message = fmt.Sprintf(
			"%s passes the floor and waits out its quarantine until %s",
			passing.Version, passing.ReleasedAt.Add(quarantine(p)).Format(time.RFC3339))
		verdict.Alternatives = alternativesOf(*passing)

		return verdict
	}

	latest := newest(pool)
	verdict.Code = regtypes.VerdictDeniedOverFloor
	verdict.Message = fmt.Sprintf(
		"every release in track %s carries a vulnerability at or above the %s floor; newest is %s (%v); re-request an explicit version to choose one",
		trackFor(req, latest), p.AdmissionMaxSeverity, latest.Version, latest.Vulns)
	verdict.Alternatives = alternativesOf(latest)

	return verdict
}

// evaluateExact handles a request naming an exact version. Nothing is ever
// swapped under the requester.
func evaluateExact(verdict regtypes.Verdict, req regtypes.Request, available []regtypes.Candidate, now time.Time, p regtypes.Params) regtypes.Verdict {
	var found *regtypes.Candidate

	for i := range available {
		if CompareVersions(available[i].Version, req.Version) == 0 {
			found = &available[i]
			break
		}
	}

	if found == nil {
		verdict.Code = regtypes.VerdictDeniedUnknown
		verdict.Message = fmt.Sprintf("upstream has no %s; newest is %s",
			req.Version, newest(available).Version)

		return verdict
	}

	if found.Vulns.Exceeds(p.AdmissionMaxSeverity) {
		verdict.Code = regtypes.VerdictDeniedOverFloor
		verdict.Message = fmt.Sprintf(
			"%s carries %v at or above the %s floor",
			found.Version, found.VulnIDs, p.AdmissionMaxSeverity)
		verdict.Alternatives = passingAlternatives(available, *found, now, p)

		return verdict
	}

	if age(*found, now) < quarantine(p) {
		verdict.Code = regtypes.VerdictDeniedQuarantined
		verdict.Message = fmt.Sprintf(
			"%s is in quarantine until %s",
			found.Version, found.ReleasedAt.Add(quarantine(p)).Format(time.RFC3339))
		verdict.Alternatives = passingAlternatives(available, *found, now, p)

		return verdict
	}

	verdict.Code = regtypes.VerdictAdopted
	verdict.Adopted = found.Version
	verdict.Track = trackFor(req, *found)
	verdict.Message = fmt.Sprintf("admitted %s (%v)", found.Version, found.Vulns)

	return verdict
}

// TrackOpenInput carries everything the track deny policies need.
type TrackOpenInput struct {
	Request regtypes.Request
	// Versions is every upstream release of the package.
	Versions []regtypes.Candidate
	// DefaultCurrent is the default track's current version, when one exists.
	DefaultCurrent *regtypes.Candidate
	// NonMajorTracks counts the package's already-open finer tracks.
	NonMajorTracks int
}

// EvaluateTrackOpen runs the deterministic deny policies: a track is a fact
// about upstream, not a preference of a consumer, so it opens only for a
// provably maintained line, never as a security regression, and never past
// the budget.
func EvaluateTrackOpen(in TrackOpenInput, now time.Time, p regtypes.Params) regtypes.Verdict {
	verdict := regtypes.Verdict{
		Package:   in.Request.Package,
		Ecosystem: in.Request.Ecosystem,
		Track:     in.Request.Track,
		DecidedAt: now,
	}

	prefix := in.Request.Track

	var inLine []regtypes.Candidate

	var lastInPrefix, successorFirst time.Time

	for _, c := range in.Versions {
		if isPrerelease(c.Version) {
			continue
		}

		if InPrefix(c.Version, prefix) {
			inLine = append(inLine, c)

			if c.ReleasedAt.After(lastInPrefix) {
				lastInPrefix = c.ReleasedAt
			}

			continue
		}

		if CompareVersions(c.Version, prefix) > 0 {
			if successorFirst.IsZero() || c.ReleasedAt.Before(successorFirst) {
				successorFirst = c.ReleasedAt
			}
		}
	}

	if len(inLine) == 0 {
		verdict.Code = regtypes.VerdictDeniedUnknown
		verdict.Message = fmt.Sprintf("upstream has no release in %s", prefix)

		return verdict
	}

	maintained := !successorFirst.IsZero() &&
		lastInPrefix.After(successorFirst) &&
		now.Sub(lastInPrefix) <= time.Duration(p.StaleAfterDays)*day

	if !maintained {
		verdict.Code = regtypes.VerdictDeniedUnmaintained
		verdict.Message = fmt.Sprintf(
			"%s is not a maintained line: upstream has released nothing into it since a successor exists; this is a pin, use a pin", prefix)

		return verdict
	}

	if in.NonMajorTracks >= p.MaxTracksPerPackage {
		verdict.Code = regtypes.VerdictDeniedOverBudget
		verdict.Message = fmt.Sprintf(
			"%s already carries %d finer tracks, the register's budget; retire one first",
			in.Request.Package, in.NonMajorTracks)

		return verdict
	}

	// A maintenance track opens at the line's head - the backports are the
	// point - so candidates order newest first here, with the floor and
	// quarantine still enforced.
	sort.Slice(inLine, func(i, j int) bool {
		return CompareVersions(inLine[i].Version, inLine[j].Version) > 0
	})

	current := firstAdmissible(inLine, now, p)
	if current == nil {
		verdict.Code = regtypes.VerdictDeniedOverFloor
		verdict.Message = fmt.Sprintf(
			"no release in %s passes the %s floor out of quarantine", prefix, p.AdmissionMaxSeverity)
		verdict.Alternatives = alternativesOf(newest(inLine))

		return verdict
	}

	if in.DefaultCurrent != nil && current.Vulns.Compare(in.DefaultCurrent.Vulns) > 0 {
		verdict.Code = regtypes.VerdictDeniedRegression
		verdict.Message = fmt.Sprintf(
			"%s (%v) is less safe than the default track's %s (%v); opening it would be a security regression",
			current.Version, current.Vulns, in.DefaultCurrent.Version, in.DefaultCurrent.Vulns)

		return verdict
	}

	verdict.Code = regtypes.VerdictAdopted
	verdict.Adopted = current.Version
	verdict.Message = fmt.Sprintf("track %s opens at %s (%v)", prefix, current.Version, current.Vulns)

	return verdict
}

// DeprecationInput carries what deprecation policy reads.
type DeprecationInput struct {
	Track regtypes.Track
	// HasSuccessor reports whether a newer line of this package exists.
	HasSuccessor bool
	// LastReleaseInPrefix is upstream's newest release inside this track.
	LastReleaseInPrefix time.Time
}

// EvaluateDeprecation is programmatic, never manual: a track deprecates when
// its advisory has no fix past the window, or when upstream stopped releasing
// into it while a successor exists. An already-deprecated track is stable.
func EvaluateDeprecation(in DeprecationInput, now time.Time, p regtypes.Params) *regtypes.Deprecation {
	if in.Track.Deprecated != nil {
		return in.Track.Deprecated
	}

	if in.Track.Advisory != nil &&
		now.Sub(in.Track.Advisory.Since) > time.Duration(p.DeprecateAfterDays)*day {
		return &regtypes.Deprecation{Reason: regtypes.DeprecationNoFix, Since: now}
	}

	if in.HasSuccessor && !in.LastReleaseInPrefix.IsZero() &&
		now.Sub(in.LastReleaseInPrefix) > time.Duration(p.StaleAfterDays)*day {
		return &regtypes.Deprecation{Reason: regtypes.DeprecationStale, Since: now}
	}

	return nil
}

// EvaluateQuiet names a track whose upstream went silent with nowhere to
// go: past the stale window with no successor line, the track stays
// current and carries the last release date, visibly. Deprecation needs a
// successor to point at; silence without one is a fact worth naming, not
// a retirement. The answer is the mark to store - nil clears it, so the
// mark heals itself when upstream releases again or a successor appears.
func EvaluateQuiet(in DeprecationInput, now time.Time, p regtypes.Params) *time.Time {
	if in.Track.Deprecated != nil || in.HasSuccessor || in.LastReleaseInPrefix.IsZero() {
		return nil
	}

	if now.Sub(in.LastReleaseInPrefix) <= time.Duration(p.StaleAfterDays)*day {
		return nil
	}

	since := in.LastReleaseInPrefix

	return &since
}

func currentVector(track regtypes.Track) regtypes.Vector {
	if len(track.History) == 0 {
		return regtypes.Vector{}
	}

	return track.History[len(track.History)-1].Vulns
}

func quarantine(p regtypes.Params) time.Duration {
	return time.Duration(p.QuarantineDays) * day
}

func age(c regtypes.Candidate, now time.Time) time.Duration {
	return now.Sub(c.ReleasedAt)
}

// poolFor narrows candidates to releases in the requested track, or in the
// highest released major when the request names none: the default track.
// Pre-releases never enter a pool; a request must name one exactly.
func poolFor(req regtypes.Request, available []regtypes.Candidate) []regtypes.Candidate {
	releases := make([]regtypes.Candidate, 0, len(available))
	for _, c := range available {
		if !isPrerelease(c.Version) {
			releases = append(releases, c)
		}
	}

	prefix := req.Track
	if prefix == "" {
		for _, c := range releases {
			if m := MajorOf(c.Version); prefix == "" || CompareVersions(m, prefix) > 0 {
				prefix = m
			}
		}
	}

	pool := make([]regtypes.Candidate, 0, len(releases))
	for _, c := range releases {
		if InPrefix(c.Version, prefix) {
			pool = append(pool, c)
		}
	}

	return pool
}

func trackFor(req regtypes.Request, c regtypes.Candidate) string {
	if req.Track != "" {
		return req.Track
	}

	return MajorOf(c.Version)
}

// sortForAdmission orders by severity vector ascending, then release date
// descending: the safest first, the freshest among equals.
func sortForAdmission(pool []regtypes.Candidate) {
	sort.SliceStable(pool, func(i, j int) bool {
		if c := pool[i].Vulns.Compare(pool[j].Vulns); c != 0 {
			return c < 0
		}

		return pool[i].ReleasedAt.After(pool[j].ReleasedAt)
	})
}

func firstPassing(pool []regtypes.Candidate, p regtypes.Params) *regtypes.Candidate {
	for i := range pool {
		if !pool[i].Vulns.Exceeds(p.AdmissionMaxSeverity) {
			return &pool[i]
		}
	}

	return nil
}

func firstAdmissible(pool []regtypes.Candidate, now time.Time, p regtypes.Params) *regtypes.Candidate {
	for i := range pool {
		if !pool[i].Vulns.Exceeds(p.AdmissionMaxSeverity) && age(pool[i], now) >= quarantine(p) {
			return &pool[i]
		}
	}

	return nil
}

func newest(pool []regtypes.Candidate) regtypes.Candidate {
	best := pool[0]
	for _, c := range pool[1:] {
		if CompareVersions(c.Version, best.Version) > 0 {
			best = c
		}
	}

	return best
}

func alternativesOf(cs ...regtypes.Candidate) []regtypes.Alternative {
	out := make([]regtypes.Alternative, 0, len(cs))
	for _, c := range cs {
		out = append(out, regtypes.Alternative{
			Version: c.Version, ReleasedAt: c.ReleasedAt, Vulns: c.Vulns,
		})
	}

	return out
}

// passingAlternatives offers what a rejected exact request could ask for
// instead: the newest version passing the floor and out of quarantine, and
// the newest overall when they differ. An alternative the policy would also
// reject is no alternative.
func passingAlternatives(available []regtypes.Candidate, rejected regtypes.Candidate, now time.Time, p regtypes.Params) []regtypes.Alternative {
	var out []regtypes.Alternative

	var pass *regtypes.Candidate

	for i := range available {
		c := available[i]
		if c.Vulns.Exceeds(p.AdmissionMaxSeverity) || age(c, now) < quarantine(p) {
			continue
		}

		if pass == nil || CompareVersions(c.Version, pass.Version) > 0 {
			pass = &available[i]
		}
	}

	if pass != nil && CompareVersions(pass.Version, rejected.Version) != 0 {
		out = append(out, alternativesOf(*pass)...)
	}

	if latest := newest(available); CompareVersions(latest.Version, rejected.Version) != 0 &&
		(pass == nil || CompareVersions(latest.Version, pass.Version) != 0) {
		out = append(out, alternativesOf(latest)...)
	}

	return out
}

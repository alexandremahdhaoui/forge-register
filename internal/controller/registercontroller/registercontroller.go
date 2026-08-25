// Package registercontroller orchestrates the register: it feeds the pure
// policy from the store and the discoverer, and persists what the policy
// decides. Every decision is written as a verdict; adopting also advances the
// track. Nothing here decides anything itself.
package registercontroller

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/discoverycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/policycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

type Controller struct {
	store     storeadapter.Store
	discovery discoverycontroller.Discoverer
	params    regtypes.Params
}

func New(store storeadapter.Store, discovery discoverycontroller.Discoverer, params regtypes.Params) *Controller {
	return &Controller{store: store, discovery: discovery, params: params}
}

// KeyedVerdict pairs a verdict with the key it was recorded under.
type KeyedVerdict struct {
	Key     string
	Verdict regtypes.Verdict
}

// Report says what one run decided. Failed names tracks whose feed could not
// answer - a broken feed must not hide the other tracks, and must not look
// like a policy decision either.
type Report struct {
	Verdicts []KeyedVerdict
	Adopted  int
	Failed   []string
}

// Evaluate walks every track: fresh discovery, the upgrade policy, advisory
// maintenance and deprecation. Not upgrading is never silent - every track
// gets a verdict every run.
func (c *Controller) Evaluate(ctx context.Context, now time.Time) (Report, error) {
	var report Report

	tracks, err := c.store.Tracks(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("evaluating: %w", err)
	}

	for _, track := range tracks {
		// Internal packages advance by proof, never by discovery: they have
		// no feed and no registry, and their door is Publish.
		if track.Ecosystem == "internal" {
			continue
		}

		candidates, snapshot, err := c.discovery.Discover(ctx, track.Ecosystem, track.Package)
		if err != nil {
			report.Failed = append(report.Failed,
				fmt.Sprintf("%s:%s: %v", track.Ecosystem, track.Package, err))

			continue
		}

		verdict := policycontroller.EvaluateUpgrade(track, candidates, now, c.params)
		verdict.OSVSnapshot = snapshot

		if verdict.Code == regtypes.VerdictAdopted {
			track, err = c.advance(ctx, track, verdict.Adopted, candidates, snapshot, "", now)
			if err != nil {
				return Report{}, err
			}

			report.Adopted++
		}

		track = c.maintain(track, candidates, now)

		if err := c.store.PutTrack(ctx, track); err != nil {
			return Report{}, fmt.Errorf("evaluating %s: %w", track.Package, err)
		}

		key := autoKey(track, now)
		if err := c.store.PutVerdict(ctx, key, verdict); err != nil {
			return Report{}, fmt.Errorf("evaluating %s: %w", track.Package, err)
		}

		report.Verdicts = append(report.Verdicts, KeyedVerdict{Key: key, Verdict: verdict})
	}

	return report, nil
}

// Process answers every pending request. Answering a request is writing its
// verdict; an adoption also creates or advances the track.
func (c *Controller) Process(ctx context.Context, now time.Time) (Report, error) {
	var report Report

	pending, err := c.store.PendingRequests(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("processing requests: %w", err)
	}

	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		request := pending[key]

		verdict, err := c.answer(ctx, request, now)
		if err != nil {
			return Report{}, fmt.Errorf("processing %s: %w", key, err)
		}

		if err := c.store.PutVerdict(ctx, key, verdict); err != nil {
			return Report{}, fmt.Errorf("processing %s: %w", key, err)
		}

		if verdict.Code == regtypes.VerdictAdopted {
			report.Adopted++
		}

		report.Verdicts = append(report.Verdicts, KeyedVerdict{Key: key, Verdict: verdict})
	}

	return report, nil
}

func (c *Controller) answer(ctx context.Context, request regtypes.Request, now time.Time) (regtypes.Verdict, error) {
	candidates, snapshot, err := c.discovery.Discover(ctx, request.Ecosystem, request.Package)
	if err != nil {
		return regtypes.Verdict{}, err
	}

	var verdict regtypes.Verdict

	switch request.Type {
	case regtypes.RequestOpenTrack:
		verdict, err = c.answerOpenTrack(ctx, request, candidates, now)
		if err != nil {
			return regtypes.Verdict{}, err
		}
	default:
		verdict = policycontroller.EvaluateAdmission(request, candidates, now, c.params)
	}

	verdict.OSVSnapshot = snapshot

	if verdict.Code == regtypes.VerdictAdopted {
		if err := c.admit(ctx, request.Ecosystem, request.Package, verdict, candidates, snapshot, now); err != nil {
			return regtypes.Verdict{}, err
		}
	}

	return verdict, nil
}

func (c *Controller) answerOpenTrack(ctx context.Context, request regtypes.Request, candidates []regtypes.Candidate, now time.Time) (regtypes.Verdict, error) {
	existing, err := c.store.TracksOf(ctx, request.Ecosystem, request.Package)
	if err != nil {
		return regtypes.Verdict{}, err
	}

	in := policycontroller.TrackOpenInput{Request: request, Versions: candidates}

	var defaultTrack *regtypes.Track

	for i, t := range existing {
		if isFiner(t.Prefix) {
			in.NonMajorTracks++

			continue
		}

		if defaultTrack == nil || compareNumeric(t.Prefix, defaultTrack.Prefix) > 0 {
			defaultTrack = &existing[i]
		}
	}

	if defaultTrack != nil {
		for i := range candidates {
			if candidates[i].Version == defaultTrack.Current {
				in.DefaultCurrent = &candidates[i]
				break
			}
		}
	}

	return policycontroller.EvaluateTrackOpen(in, now, c.params), nil
}

// admit creates or advances the track an adopted verdict names.
func (c *Controller) admit(ctx context.Context, ecosystem, pkg string, verdict regtypes.Verdict, candidates []regtypes.Candidate, snapshot string, now time.Time) error {
	prefix := verdict.Track
	if prefix == "" {
		prefix = policycontroller.MajorOf(verdict.Adopted)
	}

	track, found, err := c.store.Track(ctx, ecosystem, pkg, prefix)
	if err != nil {
		return err
	}

	if !found {
		track = regtypes.Track{Package: pkg, Ecosystem: ecosystem, Prefix: prefix, Current: ""}
	}

	if track.Current != "" && compareNumeric(verdict.Adopted, track.Current) <= 0 {
		// The track is already at or past the adopted version; nothing moves.
		return nil
	}

	track, err = c.advance(ctx, track, verdict.Adopted, candidates, snapshot, "", now)
	if err != nil {
		return err
	}

	track = c.maintain(track, candidates, now)

	return c.store.PutTrack(ctx, track)
}

// Publish is the proof door: an internal package enters when a green pipeline
// released it, carrying the revision that proved it. No feed and no
// quarantine apply - proof replaces policy.
func (c *Controller) Publish(ctx context.Context, ecosystem, pkg, version, source, provenance string, now time.Time) (KeyedVerdict, error) {
	prefix := policycontroller.MajorOf(version)

	verdict := regtypes.Verdict{
		Code: regtypes.VerdictAdopted, Package: pkg, Ecosystem: ecosystem,
		Track: prefix, Adopted: version, DecidedAt: now,
		Message: fmt.Sprintf("published by proof: revision %s", provenance),
	}

	track, found, err := c.store.Track(ctx, ecosystem, pkg, prefix)
	if err != nil {
		return KeyedVerdict{}, fmt.Errorf("publishing %s: %w", pkg, err)
	}

	if !found {
		track = regtypes.Track{Package: pkg, Ecosystem: ecosystem, Prefix: prefix}
	}

	if track.Current == "" || compareNumeric(version, track.Current) > 0 {
		track.Current = version
		track.UpdatedAt = now
		track.History = append(track.History, regtypes.Entry{
			Version: version, ReleasedAt: now, AdoptedAt: now,
			Source: source, Provenance: provenance,
		})

		if err := c.store.PutTrack(ctx, track); err != nil {
			return KeyedVerdict{}, fmt.Errorf("publishing %s: %w", pkg, err)
		}
	} else {
		verdict.Code = regtypes.VerdictUpToDate
		verdict.Adopted = ""
		verdict.Message = fmt.Sprintf("track %s is already at %s", prefix, track.Current)
	}

	key := autoKey(track, now)
	if err := c.store.PutVerdict(ctx, key, verdict); err != nil {
		return KeyedVerdict{}, fmt.Errorf("publishing %s: %w", pkg, err)
	}

	return KeyedVerdict{Key: key, Verdict: verdict}, nil
}

// advance appends the adopted version to the track's history and moves
// current.
func (c *Controller) advance(_ context.Context, track regtypes.Track, version string, candidates []regtypes.Candidate, snapshot, provenance string, now time.Time) (regtypes.Track, error) {
	entry := regtypes.Entry{
		Version: version, AdoptedAt: now, OSVSnapshot: snapshot, Provenance: provenance,
	}

	for _, cand := range candidates {
		if cand.Version == version {
			entry.ReleasedAt = cand.ReleasedAt
			entry.Vulns = cand.Vulns

			break
		}
	}

	track.Current = version
	track.UpdatedAt = now
	track.History = append(track.History, entry)

	return track, nil
}

// maintain keeps the advisory and the deprecation honest against the fresh
// snapshot: an advisory appears when current carries vulnerabilities and no
// strictly safer, newer release exists; it clears when either stops being
// true. Deprecation is policy, applied here, never by hand.
func (c *Controller) maintain(track regtypes.Track, candidates []regtypes.Candidate, now time.Time) regtypes.Track {
	var current *regtypes.Candidate

	var lastRelease time.Time

	hasSuccessor := false

	for i, cand := range candidates {
		if cand.Version == track.Current {
			current = &candidates[i]
		}

		if policycontroller.InPrefix(cand.Version, track.Prefix) {
			if cand.ReleasedAt.After(lastRelease) {
				lastRelease = cand.ReleasedAt
			}
		} else if compareNumeric(cand.Version, track.Prefix) > 0 &&
			!policycontroller.IsPrerelease(cand.Version) {
			// A line holding only pre-releases is not a successor anyone
			// can move to, so it cannot make this track stale.
			hasSuccessor = true
		}
	}

	if current != nil {
		fixExists := false

		for _, cand := range candidates {
			if policycontroller.InPrefix(cand.Version, track.Prefix) &&
				compareNumeric(cand.Version, track.Current) > 0 &&
				cand.Vulns.Compare(current.Vulns) < 0 {
				fixExists = true

				break
			}
		}

		switch {
		case (current.Vulns == regtypes.Vector{}) || fixExists:
			track.Advisory = nil
		case track.Advisory == nil:
			track.Advisory = &regtypes.Advisory{
				VulnIDs:  current.VulnIDs,
				Severity: ceiling(current.Vulns),
				Since:    now,
			}
		default:
			// The advisory stands; its since date marks when it appeared.
			track.Advisory.VulnIDs = current.VulnIDs
			track.Advisory.Severity = ceiling(current.Vulns)
		}
	}

	track.Deprecated = policycontroller.EvaluateDeprecation(policycontroller.DeprecationInput{
		Track: track, HasSuccessor: hasSuccessor, LastReleaseInPrefix: lastRelease,
	}, now, c.params)

	track.QuietSince = policycontroller.EvaluateQuiet(policycontroller.DeprecationInput{
		Track: track, HasSuccessor: hasSuccessor, LastReleaseInPrefix: lastRelease,
	}, now, c.params)

	return track
}

func ceiling(v regtypes.Vector) regtypes.Severity {
	switch {
	case v.Critical > 0:
		return regtypes.SeverityCritical
	case v.High > 0:
		return regtypes.SeverityHigh
	case v.Medium > 0:
		return regtypes.SeverityMedium
	}

	return regtypes.SeverityLow
}

// RequestKey names a request record so its verdict can mirror it.
func RequestKey(request regtypes.Request, now time.Time) string {
	return request.Ecosystem + "/" + request.Package + "/" +
		strconv.FormatInt(now.Unix(), 10) + "-" + request.Type
}

func autoKey(track regtypes.Track, now time.Time) string {
	return storeadapter.TrackKey(track.Ecosystem, track.Package, track.Prefix) +
		"/" + strconv.FormatInt(now.Unix(), 10)
}

// isFiner reports whether a prefix names a maintenance line below a major.
func isFiner(prefix string) bool {
	for _, r := range prefix {
		if r == '.' {
			return true
		}
	}

	return false
}

// compareNumeric orders two version-ish strings the way the policy does.
func compareNumeric(a, b string) int {
	return policycontroller.CompareVersions(a, b)
}

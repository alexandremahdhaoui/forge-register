// Package osvadapter reads known vulnerabilities from an OSV-shaped feed.
//
// Two rules shape this file. Both were learned from real responses rather
// than from the documentation.
//
// The feed's version filter is a hint, never the answer. Asked about
// golang.org/x/crypto at "not-a-version" the API answers 200 with 37 records
// when the truth is 36. It does not error and it does not return everything;
// it returns a wrong answer that looks right. So a package is asked WITHOUT a
// version, and the ranges each record publishes decide which of our versions
// it covers. The filtered query still rides along in the same batch, purely
// so a disagreement can be reported.
//
// An empty answer is not a clean answer. A package with no vulnerabilities, a
// package the feed has never heard of, and a request it could not read all
// come back as 200 with the body "{}". Every version therefore carries an
// outcome naming which of those happened, and the reason travels with it.
package osvadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// userAgent identifies us to every feed we read. crates.io answers 403 to a
// request without one, which is what a whole afternoon of "the network is
// blocked" turned out to be.
const userAgent = "forge-register (+https://github.com/alexandremahdhaoui/forge-register)"

// maxPages bounds the pagination loop. The feed pages at a thousand records
// per query and hands back a token per result; a token that never clears is
// a broken feed, and looping on it forever is worse than failing.
const maxPages = 64

// maxQueriesPerBatch is OSV's own cap on one querybatch request. Past it the
// endpoint answers 400 {"code":3,"message":"too many queries"}.
//
// The register sends one query per published version, so a package crosses
// this the moment it has published a thousand releases - and the packages
// that get there are the oldest, most depended upon and most attacked. Three
// tracks in one real workspace were silently unmeasured: typescript at 3809
// versions, @types/node at 2358, typescript-eslint at 1549. Every package
// below the line was measured; every package above it was not.
//
// The boundary is measured against the live API, not assumed: 1000 answers
// 200 and 1001 answers 400.
const maxQueriesPerBatch = 1000

// Querier reads what a feed knows about a package's versions.
type Querier interface {
	Vulns(ctx context.Context, ecosystem, pkg string, versions []string) (map[string]regtypes.Answer, string, error)
}

// ecosystems maps register ecosystems to OSV's names. Internal packages enter
// by proof, not discovery - but they are public Go modules and their
// vulnerabilities are as real as anyone's, so they are asked as Go.
var ecosystems = map[string]string{
	"go":         "Go",
	"internal":   "Go",
	"rust":       "crates.io",
	"python":     "PyPI",
	"typescript": "npm",
}

// HTTP implements Querier over OSV's querybatch and vuln endpoints.
type HTTP struct {
	client *http.Client
	base   string

	// warn reports what a human needs to know but must not be stopped by.
	// It is a field so a test can read the warnings instead of the terminal.
	warn func(format string, args ...any)

	// records is every record read so far, by id. A record is immutable, so
	// one fetch serves every version and every alias that names it. Without
	// it a single package cost 111 requests and the next version of the same
	// package cost 111 more.
	mu      sync.Mutex
	records map[string]record
}

var _ Querier = (*HTTP)(nil)

// Option configures the adapter.
type Option func(*HTTP)

// WithWarner sends warnings somewhere other than stderr.
func WithWarner(f func(format string, args ...any)) Option {
	return func(h *HTTP) { h.warn = f }
}

func New(client *http.Client, base string, opts ...Option) *HTTP {
	if client == nil {
		client = http.DefaultClient
	}

	if base == "" {
		base = "https://api.osv.dev"
	}

	h := &HTTP{
		client:  client,
		base:    base,
		records: map[string]record{},
		warn: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "WARN "+format+"\n", args...)
		},
	}

	for _, o := range opts {
		o(h)
	}

	return h
}

// batchQuery is one entry of a querybatch request. Version is omitted for the
// authoritative package-wide query.
type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResult struct {
	// querybatch answers an id and a modified timestamp per record. Only
	// the id is used - the full record is fetched by id, and adoption dates
	// come from the register - so the timestamp is not declared. A field
	// declared and never used reads as guarded to the unread-fields gate,
	// which subtracts struct tags, and is guarded by nothing.
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// Vulns answers what the feed knows about each version.
//
// One HTTP call carries every query: the package-wide one that decides the
// answer, and one filtered query per version whose only job is to disagree
// out loud.
func (h *HTTP) Vulns(ctx context.Context, ecosystem, pkg string, versions []string) (map[string]regtypes.Answer, string, error) {
	out := make(map[string]regtypes.Answer, len(versions))

	osvEco, ok := ecosystems[ecosystem]
	if !ok {
		reason := fmt.Sprintf("ecosystem %q has no vulnerability feed", ecosystem)
		for _, v := range versions {
			out[v] = regtypes.Answer{Outcome: regtypes.OutcomeNotFound, Reason: reason}
		}

		return out, digestOf(nil), nil
	}

	// A version that is not a version cannot be compared against a range.
	// Left alone it sorts below everything, so every advisory opening at
	// "introduced: 0" would appear to cover it - which is the feed's own bug
	// reproduced locally rather than caught. Our own data being wrong is not
	// a feed condition, so it fails rather than warns.
	for _, v := range versions {
		if !regtypes.IsVersion(v) {
			return nil, "", fmt.Errorf("%s %s: %q is not a version, so no published range can be evaluated",
				ecosystem, pkg, v)
		}
	}

	queries := make([]batchQuery, 0, len(versions)+1)

	all := batchQuery{}
	all.Package.Name = pkg
	all.Package.Ecosystem = osvEco
	queries = append(queries, all)

	for _, v := range versions {
		q := batchQuery{Version: v}
		q.Package.Name = pkg
		q.Package.Ecosystem = osvEco
		queries = append(queries, q)
	}

	results, err := h.queryBatch(ctx, queries)
	if err != nil {
		// A feed we could not reach measured nothing. Saying so is the
		// whole point: a zero here used to be indistinguishable from a
		// package that is genuinely clean.
		//
		// A refusal is not the same as an outage, and the record says
		// which. The two need opposite responses - wait and retry, or fix
		// the caller - and calling a 400 unreachable sent a reader to
		// check egress and firewalls for a batch that was simply too
		// large. Either way nothing was measured, so neither blocks.
		reason := fmt.Sprintf("the vulnerability feed could not be reached: %v", err)
		if errors.Is(err, ErrClientRequest) {
			reason = fmt.Sprintf("the vulnerability feed refused the request, so nothing was measured: %v", err)
		}
		h.warn("%s %s: %s - nothing was checked", ecosystem, pkg, reason)

		for _, v := range versions {
			out[v] = regtypes.Answer{Outcome: regtypes.OutcomeUnreachable, Reason: reason}
		}

		return out, digestOf(nil), nil
	}

	// not-found is decided before withdrawal, on what the feed actually
	// returned. A package whose every record was later withdrawn is one the
	// feed knows and has nothing to say about, which is clean; calling that
	// not-found would put a measured package back in the unmeasured bucket.
	if len(results[0].Vulns) == 0 {
		reason := fmt.Sprintf("the feed carries no record for %s in %s, so nothing was measured", pkg, osvEco)
		h.warn("%s %s: %s", ecosystem, pkg, reason)

		for _, v := range versions {
			out[v] = regtypes.Answer{Outcome: regtypes.OutcomeNotFound, Reason: reason}
		}

		return out, digestOf([]string{pkg + " not-found"}), nil
	}

	records, err := h.recordsOf(ctx, results[0])
	if err != nil {
		// One record failing to load is the same condition as the batch
		// failing: the feed did not answer, so nothing was measured. It used
		// to abort the whole run - and in Process, after verdicts had already
		// been written - which made a single 429 during rate limiting worse
		// than an outage.
		reason := fmt.Sprintf("the vulnerability feed could not be read: %v", err)
		h.warn("%s %s: %s - nothing was checked", ecosystem, pkg, reason)

		for _, v := range versions {
			out[v] = regtypes.Answer{Outcome: regtypes.OutcomeUnreachable, Reason: reason}
		}

		return out, digestOf(nil), nil
	}

	snapshot := make([]string, 0, len(versions))

	for i, version := range versions {
		vulns := h.match(ctx, records, osvEco, pkg, version)

		// Every version answered gets a snapshot line, even a clean one.
		// Without it a package with no vulnerabilities digests to the
		// sha256 of nothing, which is also what a feed that was never
		// asked digests to.
		snapshot = append(snapshot, version+" queried "+strconv.Itoa(len(records))+" records")

		for _, v := range vulns {
			snapshot = append(snapshot, version+" "+v.ID+" "+string(v.Severity)+
				" fixed="+strings.Join(v.FixedIn, ",")+
				" imports="+strings.Join(v.AffectedImports, ","))
		}

		h.reportDisagreement(ecosystem, pkg, version, results[i+1], vulns)

		answer := regtypes.Answer{Outcome: regtypes.OutcomeClean, Vulns: vulns}
		if len(vulns) > 0 {
			answer.Outcome = regtypes.OutcomeFindings
			answer.Reason = fmt.Sprintf("%d published range(s) cover %s", len(vulns), version)
		} else {
			answer.Reason = fmt.Sprintf(
				"the feed carries %d record(s) for %s and none of their ranges cover %s",
				len(records), pkg, version)
		}

		out[version] = answer
	}

	return out, digestOf(snapshot), nil
}

// reportDisagreement says out loud when our range walk and the feed's own
// filter reach different answers. Neither side is silenced: the local answer
// is the one used, and the difference is printed so we learn how often the
// filter is wrong before deciding whether to keep sending it.
func (h *HTTP) reportDisagreement(ecosystem, pkg, version string, feed batchResult, ours []regtypes.Vuln) {
	theirs := map[string]bool{}
	for _, v := range feed.Vulns {
		theirs[v.ID] = true
	}

	mine := map[string]bool{}
	for _, v := range ours {
		mine[v.ID] = true
	}

	var extra, missing []string

	for id := range theirs {
		if !mine[id] {
			extra = append(extra, id)
		}
	}

	for id := range mine {
		if !theirs[id] {
			missing = append(missing, id)
		}
	}

	sort.Strings(extra)
	sort.Strings(missing)

	if len(extra) > 0 {
		h.warn("%s %s %s: the feed's own filter returned %s but no published range covers this version - ignoring it",
			ecosystem, pkg, version, strings.Join(extra, ", "))
	}

	if len(missing) > 0 {
		h.warn("%s %s %s: a published range covers this version for %s but the feed's own filter left it out - counting it",
			ecosystem, pkg, version, strings.Join(missing, ", "))
	}
}

// queryBatch runs one querybatch call and follows every page token it hands
// back. Tokens arrive per result, not per response, so a second page asks
// only about the queries that were truncated and the answers are merged back
// into their original slots.
// queryBatch answers one result per query, in the order asked.
//
// The queries are chunked to OSV's per-request cap and the answers stitched
// back by index. The endpoint is positionally aligned, so a chunk's results
// map onto the slice it came from with plain arithmetic.
func (h *HTTP) queryBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	if len(queries) > maxQueriesPerBatch {
		merged := make([]batchResult, 0, len(queries))

		for start := 0; start < len(queries); start += maxQueriesPerBatch {
			end := min(start+maxQueriesPerBatch, len(queries))

			chunk, err := h.queryBatch(ctx, queries[start:end])
			if err != nil {
				return nil, err
			}

			merged = append(merged, chunk...)
		}

		return merged, nil
	}

	return h.queryOneBatch(ctx, queries)
}

func (h *HTTP) queryOneBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	merged := make([]batchResult, len(queries))

	pending := make([]int, len(queries))
	for i := range queries {
		pending[i] = i
	}

	page := queries

	for round := 0; len(pending) > 0; round++ {
		if round >= maxPages {
			return nil, fmt.Errorf("the feed kept paging past %d rounds", maxPages)
		}

		var out struct {
			Results []batchResult `json:"results"`
		}

		if err := h.postJSON(ctx, h.base+"/v1/querybatch", map[string]any{"queries": page}, &out); err != nil {
			return nil, err
		}

		if len(out.Results) != len(page) {
			return nil, fmt.Errorf("the feed answered %d of %d queries", len(out.Results), len(page))
		}

		var (
			next     []batchQuery
			nextSlot []int
		)

		for i, r := range out.Results {
			slot := pending[i]
			merged[slot].Vulns = append(merged[slot].Vulns, r.Vulns...)

			if r.NextPageToken == "" {
				continue
			}

			q := queries[slot]
			q.PageToken = r.NextPageToken
			next = append(next, q)
			nextSlot = append(nextSlot, slot)
		}

		page, pending = next, nextSlot
	}

	return merged, nil
}

// record is one OSV vulnerability, read whole.
type record struct {
	ID          string
	Severity    regtypes.Severity
	Withdrawn   bool
	Aliases     []string
	PublishedAt time.Time
	Affected    []affected
}

// affected is one affected block: a package, its ranges and its import scope.
type affected struct {
	Name      string
	Ecosystem string
	Versions  []string
	Ranges    []versionRange
	Imports   []string
}

type versionRange struct {
	Type   string
	Events []rangeEvent
}

type rangeEvent struct {
	Introduced   string
	Fixed        string
	LastAffected string
	Limit        string
}

// recordsOf fetches every record the package-wide query named, whole.
func (h *HTTP) recordsOf(ctx context.Context, all batchResult) ([]record, error) {
	seen := map[string]bool{}
	out := make([]record, 0, len(all.Vulns))

	for _, v := range all.Vulns {
		if seen[v.ID] {
			continue
		}

		seen[v.ID] = true

		r, err := h.recordOf(ctx, v.ID)
		if err != nil {
			return nil, err
		}

		// A withdrawn record is one the feed took back. It is not an
		// advisory any more and must not gate anything.
		if r.Withdrawn {
			continue
		}

		out = append(out, r)
	}

	return out, nil
}

// match decides, from the records themselves, which advisories cover one
// version. This is the whole reason the package-wide query exists: the
// answer comes from what the feed published, never from what it filtered.
func (h *HTTP) match(ctx context.Context, records []record, osvEco, pkg, version string) []regtypes.Vuln {
	var out []regtypes.Vuln

	for _, r := range records {
		for _, a := range r.Affected {
			if a.Name != pkg || baseEcosystem(a.Ecosystem) != osvEco {
				continue
			}

			covered, why := coversVersion(a, version)
			if !covered {
				continue
			}

			// The alias hop happens here, not while reading every record the
			// feed carries: it costs a round trip, and a record that covers
			// none of our versions was about to be discarded.
			if r.Severity == "" {
				r.Severity = h.severityFromAliases(ctx, r.Aliases)
			}

			out = append(out, vulnOf(r, a, why))

			break
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	return out
}

// vulnOf folds one matched record into the finding a consumer reads.
//
// Everything comes from the affected block that matched, never from the
// record as a whole. One record routinely covers several packages: the
// golang.org/x/net advisories carry a block for the module and another for
// the Go standard library, each with its own ranges and its own import
// scope. Unioning them reports the stdlib's fixed Go version as a fix for
// the module, and tells a consumer that importing net/http puts them inside
// a golang.org/x/net advisory. Both are wrong, and both look plausible.
func vulnOf(r record, a affected, why string) regtypes.Vuln {
	introduced := map[string]bool{}
	fixed := map[string]bool{}
	last := map[string]bool{}

	for _, vr := range a.Ranges {
		for _, e := range vr.Events {
			if e.Introduced != "" {
				introduced[e.Introduced] = true
			}

			if e.Fixed != "" {
				fixed[e.Fixed] = true
			}

			if e.LastAffected != "" {
				last[e.LastAffected] = true
			}
		}
	}

	// An import entry with no path is not a scope. Carried through, the empty
	// string reads as a package everything imports.
	paths := map[string]bool{}

	for _, p := range a.Imports {
		if p != "" {
			paths[p] = true
		}
	}

	return regtypes.Vuln{
		ID:              r.ID,
		Severity:        r.Severity,
		PublishedAt:     r.PublishedAt,
		Introduced:      sortedKeys(introduced),
		FixedIn:         sortedKeys(fixed),
		LastAffected:    sortedKeys(last),
		AffectedImports: sortedKeys(paths),
		MatchedRange:    why,
	}
}

// coversVersion walks one affected block the way the OSV specification
// defines it. An explicit versions list is an exact membership test. A range
// is a walk over its events, each one opening or closing the affected window.
//
// Two things the specification is explicit about and the obvious reading is
// not.
//
// Events are sorted before the walk. OSV says sorting in the document is
// recommended but not required, and its reference algorithm sorts. Walking
// published order instead means a record that lists {fixed 1.0.0} before
// {introduced 0} - schema-valid, and nothing rejects it - would report every
// version of the package as affected forever.
//
// Limits are a separate test, not another window-closer. A version is inside
// a range only if it is below at least one limit, and "*" is infinity.
// Treating a limit as a sequential close made "*" cancel the whole range, and
// made a second, higher limit shrink the window instead of widening it. Both
// are false negatives.
//
// GIT ranges are skipped: they are commit hashes, and comparing a semver
// against a sha answers nothing.
func coversVersion(a affected, version string) (bool, string) {
	for _, v := range a.Versions {
		if regtypes.CompareVersions(v, version) == 0 {
			return true, "listed explicitly in affected.versions"
		}
	}

	for _, vr := range a.Ranges {
		if vr.Type == "GIT" {
			continue
		}

		if !beforeLimits(vr.Events, version) {
			continue
		}

		inside := false
		why := ""

		for _, e := range sortedEvents(vr.Events) {
			switch {
			case e.Introduced != "":
				// "0" means from the beginning of time.
				if e.Introduced == "0" || regtypes.CompareVersions(version, e.Introduced) >= 0 {
					inside = true
					why = "introduced " + e.Introduced
				}
			case e.Fixed != "":
				if regtypes.CompareVersions(version, e.Fixed) >= 0 {
					inside = false
				} else if inside {
					why += ", fixed in " + e.Fixed
				}
			case e.LastAffected != "":
				if regtypes.CompareVersions(version, e.LastAffected) > 0 {
					inside = false
				} else if inside {
					why += ", last affected " + e.LastAffected
				}
			}
		}

		if inside {
			return true, why
		}
	}

	return false, ""
}

// beforeLimits answers the specification's own pre-test: with no limits every
// version passes, and with limits a version must be below at least one.
func beforeLimits(events []rangeEvent, version string) bool {
	found := false

	for _, e := range events {
		if e.Limit == "" {
			continue
		}

		found = true

		// "*" is infinity, so nothing is ever above it.
		if e.Limit == "*" || regtypes.CompareVersions(version, e.Limit) < 0 {
			return true
		}
	}

	return !found
}

// sortedEvents orders a range's events by version, the way the reference
// algorithm does. Limits take no part in the walk, so they are dropped here
// and answered by beforeLimits instead. An introduced event sorts first at an
// equal version: that version is affected from it.
func sortedEvents(in []rangeEvent) []rangeEvent {
	out := make([]rangeEvent, 0, len(in))

	for _, e := range in {
		if e.Limit == "" {
			out = append(out, e)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		vi, ri := eventVersion(out[i])
		vj, rj := eventVersion(out[j])

		// "0" opens the range and always sorts first.
		switch {
		case vi == "0" && vj != "0":
			return true
		case vj == "0" && vi != "0":
			return false
		}

		if c := regtypes.CompareVersions(vi, vj); c != 0 {
			return c < 0
		}

		return ri < rj
	})

	return out
}

// eventVersion answers an event's version and its rank at an equal version:
// introduced first, so a version named by both is affected.
func eventVersion(e rangeEvent) (string, int) {
	switch {
	case e.Introduced != "":
		return e.Introduced, 0
	case e.Fixed != "":
		return e.Fixed, 1
	case e.LastAffected != "":
		return e.LastAffected, 1
	}

	return "", 2
}

// baseEcosystem drops the suffix an ecosystem may carry. OSV writes
// "Debian:11" and "Alpine:v3.18"; the part before the colon is the ecosystem.
func baseEcosystem(name string) string {
	base, _, _ := strings.Cut(name, ":")

	return base
}

// recordOf reads one vulnerability whole.
//
// Severity is resolved in three steps because no single field carries it.
// Measured over 138 real records: the database's own word covers 56%, a CVSS
// vector covers a further 6%, and 38% publish neither - of which 43 of 53
// name an alias that does. So the word is preferred, then the vector, then
// the aliases, and only after all three does severity stay unknown.
//
// depth guards the alias hop: one hop, never a cycle.
func (h *HTTP) recordOf(ctx context.Context, id string) (record, error) {
	// One fetch per id, however many versions ask about it and however many
	// records name it as an alias. Without this a single package cost 111
	// requests: 55 records plus an alias hop for each of them, and the next
	// version of the same package cost 111 more.
	h.mu.Lock()
	cached, ok := h.records[id]
	h.mu.Unlock()

	if ok {
		return cached, nil
	}

	got, err := h.fetchRecord(ctx, id)
	if err != nil {
		return record{}, err
	}

	h.mu.Lock()
	h.records[id] = got
	h.mu.Unlock()

	return got, nil
}

func (h *HTTP) fetchRecord(ctx context.Context, id string) (record, error) {
	var body struct {
		ID               string   `json:"id"`
		Withdrawn        string   `json:"withdrawn"`
		Published        string   `json:"published"`
		Aliases          []string `json:"aliases"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Versions []string `json:"versions"`
			Ranges   []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
					Limit        string `json:"limit"`
				} `json:"events"`
			} `json:"ranges"`
			EcosystemSpecific struct {
				Imports []struct {
					Path string `json:"path"`
				} `json:"imports"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}

	if err := h.getJSON(ctx, h.base+"/v1/vulns/"+id, id, &body); err != nil {
		return record{}, err
	}

	out := record{ID: id, Withdrawn: body.Withdrawn != "", Aliases: body.Aliases}

	// The advisory's own date, not ours. It is what a consumer reads and
	// what arms auto-deprecation downstream.
	if at, err := time.Parse(time.RFC3339, body.Published); err == nil {
		out.PublishedAt = at
	}

	out.Severity = severityOfWord(body.DatabaseSpecific.Severity)

	if out.Severity == "" {
		for _, s := range body.Severity {
			if sev, ok := severityOfVector(s.Type, s.Score); ok {
				out.Severity = sev

				break
			}
		}
	}

	for _, a := range body.Affected {
		block := affected{
			Name:      a.Package.Name,
			Ecosystem: a.Package.Ecosystem,
			Versions:  a.Versions,
		}

		for _, r := range a.Ranges {
			vr := versionRange{Type: r.Type}
			for _, e := range r.Events {
				vr.Events = append(vr.Events, rangeEvent{
					Introduced:   e.Introduced,
					Fixed:        e.Fixed,
					LastAffected: e.LastAffected,
					Limit:        e.Limit,
				})
			}

			block.Ranges = append(block.Ranges, vr)
		}

		for _, imp := range a.EcosystemSpecific.Imports {
			if imp.Path != "" {
				block.Imports = append(block.Imports, imp.Path)
			}
		}

		out.Affected = append(out.Affected, block)
	}

	return out, nil
}

// severityFromAliases asks the records this one is an alias of. A Go or PyPI
// advisory routinely publishes no severity while the GitHub record it aliases
// publishes one for the same vulnerability.
//
// This is asked only for a record that matched a version we hold. Asking it
// for every record the feed carries cost one round trip each, for records
// that were about to be discarded. An alias's own aliases are not followed:
// one hop, so a cycle cannot exist rather than being bounded out of one.
func (h *HTTP) severityFromAliases(ctx context.Context, aliases []string) regtypes.Severity {
	for _, alias := range aliases {
		other, err := h.recordOf(ctx, alias)
		if err != nil {
			// An alias we cannot read is not a failure of this record.
			continue
		}

		if other.Severity != "" {
			return other.Severity
		}
	}

	return ""
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

func (h *HTTP) getJSON(ctx context.Context, u, what string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", what, err)
	}

	req.Header.Set("User-Agent", userAgent)

	res, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("reading vulnerability %s: %w", what, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("reading vulnerability %s: status %d", what, res.StatusCode)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading vulnerability %s: %w", what, err)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding vulnerability %s: %w", what, err)
	}

	return nil
}

// ErrClientRequest is a request the feed understood and refused. It is not
// an unreachable feed: the two need opposite responses, one is wait and
// retry and the other is fix the caller, and reporting a 400 as a network
// problem sent a reader to check egress and firewalls for a batch that was
// simply too large.
var ErrClientRequest = errors.New("the feed refused the request")

// statusError carries the feed's own words. OSV answers a rejected batch
// with {"code":3,"message":"too many queries"}, which names the problem
// exactly; substituting our own wording turned a thirty second diagnosis
// into a bisect against the live API.
func statusError(u string, res *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	said := strings.TrimSpace(string(body))

	var parsed struct {
		Message string `json:"message"`
	}

	if json.Unmarshal(body, &parsed) == nil && parsed.Message != "" {
		said = parsed.Message
	}

	if said == "" {
		said = "no message"
	}

	if res.StatusCode >= 400 && res.StatusCode < 500 {
		return fmt.Errorf("%w: posting %s: status %d: %s",
			ErrClientRequest, u, res.StatusCode, said)
	}

	return fmt.Errorf("posting %s: status %d: %s", u, res.StatusCode, said)
}

func (h *HTTP) postJSON(ctx context.Context, u string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encoding request for %s: %w", u, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building request for %s: %w", u, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	res, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("posting %s: %w", u, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return statusError(u, res)
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading %s: %w", u, err)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s: %w", u, err)
	}

	return nil
}

// digestOf canonicalises the snapshot lines so the digest is stable whatever
// order the feed answered in. An empty snapshot digests to the sha256 of
// nothing, which is exactly what a record that was never measured should
// carry - and why the outcome is stored beside it rather than inferred.
func digestOf(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)

	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))

	return "sha256:" + hex.EncodeToString(sum[:8])
}

// Package discoverycontroller merges what the registries release with what
// the vulnerability feed knows: candidates with severity vectors, plus the
// snapshot digest every verdict cites.
package discoverycontroller

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/registryadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Discoverer answers one package's candidates and the snapshot behind them.
type Discoverer interface {
	Discover(ctx context.Context, ecosystem, pkg string) ([]regtypes.Candidate, string, error)
	// Refresh re-asks only the vulnerability feed over versions handed in:
	// the path for tracks whose versions enter by proof rather than
	// discovery, where the track's own current version is the candidate.
	Refresh(ctx context.Context, ecosystem, pkg string, published []regtypes.Candidate) ([]regtypes.Candidate, string, error)
}

type Controller struct {
	registries registryadapter.Lister
	osv        osvadapter.Querier
}

var _ Discoverer = (*Controller)(nil)

func New(registries registryadapter.Lister, osv osvadapter.Querier) *Controller {
	return &Controller{registries: registries, osv: osv}
}

func (c *Controller) Discover(ctx context.Context, ecosystem, pkg string) ([]regtypes.Candidate, string, error) {
	candidates, err := c.registries.Versions(ctx, ecosystem, pkg)
	if err != nil {
		return nil, "", fmt.Errorf("discovering %s:%s: %w", ecosystem, pkg, err)
	}

	return c.annotate(ctx, ecosystem, pkg, candidates)
}

// Refresh annotates versions the caller already holds - proof-published
// ones - with fresh vectors, touching no registry.
func (c *Controller) Refresh(ctx context.Context, ecosystem, pkg string, published []regtypes.Candidate) ([]regtypes.Candidate, string, error) {
	return c.annotate(ctx, ecosystem, pkg, published)
}

func (c *Controller) annotate(ctx context.Context, ecosystem, pkg string, candidates []regtypes.Candidate) ([]regtypes.Candidate, string, error) {
	versions := make([]string, 0, len(candidates))
	for _, c := range candidates {
		versions = append(versions, c.Version)
	}

	vulns, snapshot, err := c.osv.Vulns(ctx, ecosystem, pkg, versions)
	if err != nil {
		return nil, "", fmt.Errorf("discovering %s:%s: %w", ecosystem, pkg, err)
	}

	for i := range candidates {
		answer := vulns[candidates[i].Version]
		candidates[i].Vulns = regtypes.VectorOf(answer.Vulns)
		candidates[i].Outcome = answer.Outcome
		candidates[i].Reason = answer.Reason
		candidates[i].VulnIDs = nil
		candidates[i].VulnSeverities = nil
		candidates[i].FixedIn = nil
		candidates[i].AffectedImports = nil
		candidates[i].PublishedAt = time.Time{}

		fixes := map[string]bool{}
		imports := map[string]bool{}

		for _, v := range answer.Vulns {
			candidates[i].VulnIDs = append(candidates[i].VulnIDs, v.ID)
			candidates[i].VulnSeverities = append(candidates[i].VulnSeverities, v.Severity)

			for _, f := range v.FixedIn {
				fixes[f] = true
			}

			for _, imp := range v.AffectedImports {
				imports[imp] = true
			}

			// The oldest finding dates the advisory: it is how long this has
			// been true, not how long we have known.
			if !v.PublishedAt.IsZero() &&
				(candidates[i].PublishedAt.IsZero() || v.PublishedAt.Before(candidates[i].PublishedAt)) {
				candidates[i].PublishedAt = v.PublishedAt
			}
		}

		candidates[i].FixedIn = sortedKeys(fixes)
		candidates[i].AffectedImports = sortedKeys(imports)
	}

	return candidates, snapshot, nil
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

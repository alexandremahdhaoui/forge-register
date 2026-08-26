// Package discoverycontroller merges what the registries release with what
// the vulnerability feed knows: candidates with severity vectors, plus the
// snapshot digest every verdict cites.
package discoverycontroller

import (
	"context"
	"fmt"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/registryadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// Discoverer answers one package's candidates and the snapshot behind them.
type Discoverer interface {
	Discover(ctx context.Context, ecosystem, pkg string) ([]regtypes.Candidate, string, error)
	// Refresh re-asks only the vulnerability feed over versions handed in:
	// the path for tracks whose versions enter by proof rather than
	// discovery, where the published history IS the candidate list.
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

// Refresh annotates versions the caller already holds - a proof-published
// history - with fresh vectors, touching no registry.
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
		affecting := vulns[candidates[i].Version]
		candidates[i].Vulns = regtypes.VectorOf(affecting)
		candidates[i].VulnIDs = nil

		for _, v := range affecting {
			candidates[i].VulnIDs = append(candidates[i].VulnIDs, v.ID)
		}
	}

	return candidates, snapshot, nil
}

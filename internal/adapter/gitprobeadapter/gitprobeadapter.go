// Package gitprobeadapter asks a remote repository one question: where
// is HEAD. The status verb uses it to say when an internal track has
// fallen behind the repo it catalogs - staleness a consumer otherwise
// discovers only when a resolved tuple fails to build.
package gitprobeadapter

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Prober answers a remote's HEAD sha.
type Prober struct{}

// New builds the prober.
func New() Prober {
	return Prober{}
}

// RemoteHead answers the full sha the remote's HEAD points at.
func (Prober) RemoteHead(ctx context.Context, url string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "ls-remote", url, "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("asking %s for HEAD: %w", url, err)
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("asking %s for HEAD: empty answer", url)
	}

	return fields[0], nil
}

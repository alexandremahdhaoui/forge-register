package gitprobeadapter_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/gitprobeadapter"
)

// A file:// remote keeps the probe hermetic: git ls-remote answers a
// local repository exactly like a hosted one.
func TestRemoteHeadAnswersTheSha(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	gitIn := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	gitIn("init", "-b", "main")
	gitIn("config", "user.email", "t@example.com")
	gitIn("config", "user.name", "t")
	gitIn("commit", "--allow-empty", "-m", "one")

	head, err := gitprobeadapter.New().RemoteHead(t.Context(), "file://"+filepath.ToSlash(dir))
	require.NoError(t, err)
	require.Len(t, head, 40)

	rev := exec.Command("git", "rev-parse", "HEAD")
	rev.Dir = dir
	want, err := rev.Output()
	require.NoError(t, err)
	require.Equal(t, string(want[:40]), head)
}

func TestRemoteHeadFailsLoudOnAMissingRemote(t *testing.T) {
	t.Parallel()

	_, err := gitprobeadapter.New().RemoteHead(t.Context(), "file:///nowhere/at/all")
	require.ErrorContains(t, err, "asking file:///nowhere/at/all for HEAD")
}

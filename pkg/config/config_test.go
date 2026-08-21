package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/pkg/config"
)

const valid = `
name: golden-register
state:
  engine: go://github.com/alexandremahdhaoui/forge-ci/cmd/ci-state-git
  spec:
    path: .
params:
  quarantineDays: 0
  admissionMaxSeverity: critical
  deprecateAfterDays: 30
  staleAfterDays: 180
  deprecatedGraceDays: 30
  maxTracksPerPackage: 2
`

func TestParseAcceptsAValidConfig(t *testing.T) {
	r, err := config.Parse([]byte(valid))
	require.NoError(t, err)
	require.Equal(t, "golden-register", r.Name)
	require.Equal(t, ".", r.State.Spec["path"])
	require.Equal(t, 2, r.Params.MaxTracksPerPackage)
}

func TestParseRefusesAnUnknownKey(t *testing.T) {
	_, err := config.Parse([]byte(valid + "\nquarantine: 3\n"))
	require.Error(t, err, "a typo in a policy knob is a bug you want reported, not swallowed")
}

func TestValidateNamesEveryProblemAtOnce(t *testing.T) {
	_, err := config.Parse([]byte(`
name: ""
state:
  engine: http://nope
params:
  quarantineDays: -1
  admissionMaxSeverity: severe
  deprecateAfterDays: 30
  staleAfterDays: 180
  deprecatedGraceDays: 30
  maxTracksPerPackage: 0
`))
	require.ErrorIs(t, err, config.ErrInvalid)

	for _, expect := range []string{
		"name is required",
		"not a go:// or alias:// URI",
		"quarantineDays cannot be negative",
		`"severe" is not critical, high, medium or low`,
		"maxTracksPerPackage must be at least 1",
	} {
		require.ErrorContains(t, err, expect)
	}
}

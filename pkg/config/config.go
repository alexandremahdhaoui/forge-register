// Package config parses forge-register.yaml: the register instance's state
// engine, feeds and policy parameters. Policy is register-level - a consumer
// can read these knobs and can never set them.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// DefaultPath is where a register instance keeps its config.
const DefaultPath = "forge-register.yaml"

var (
	uriPattern = regexp.MustCompile(`^(go|alias)://.+`)

	// ErrInvalid wraps every validation problem, all reported at once.
	ErrInvalid = errors.New("invalid register config")
)

type Register struct {
	Name       string     `json:"name"`
	State      State      `json:"state"`
	Registries Registries `json:"registries,omitempty"`
	OSV        OSV        `json:"osv,omitempty"`
	Params     Params     `json:"params"`
}

type State struct {
	Engine string         `json:"engine"`
	Spec   map[string]any `json:"spec,omitempty"`
}

// Registries overrides the upstream registries, for tests and mirrors.
type Registries struct {
	GoProxy string `json:"goProxy,omitempty"`
	Crates  string `json:"crates,omitempty"`
	PyPI    string `json:"pypi,omitempty"`
	NPM     string `json:"npm,omitempty"`
}

type OSV struct {
	Base string `json:"base,omitempty"`
}

// Params are the policy knobs, register-level by design.
type Params struct {
	QuarantineDays       int    `json:"quarantineDays"`
	AdmissionMaxSeverity string `json:"admissionMaxSeverity"`
	DeprecateAfterDays   int    `json:"deprecateAfterDays"`
	StaleAfterDays       int    `json:"staleAfterDays"`
	DeprecatedGraceDays  int    `json:"deprecatedGraceDays"`
	MaxTracksPerPackage  int    `json:"maxTracksPerPackage"`
}

// Parse reads the config strictly: an unknown key is an error, because a typo
// in a policy knob is a bug you want reported, not swallowed.
func Parse(data []byte) (Register, error) {
	var r Register
	if err := yaml.UnmarshalStrict(data, &r); err != nil {
		return Register{}, fmt.Errorf("parsing register config: %w", err)
	}

	if err := r.Validate(); err != nil {
		return Register{}, err
	}

	return r, nil
}

// Validate names every problem at once.
func (r Register) Validate() error {
	var problems []string

	if strings.TrimSpace(r.Name) == "" {
		problems = append(problems, "name is required")
	}

	if strings.TrimSpace(r.State.Engine) == "" {
		problems = append(problems, "state.engine is required")
	} else if !uriPattern.MatchString(r.State.Engine) {
		problems = append(problems, fmt.Sprintf(
			"state.engine %q is not a go:// or alias:// URI", r.State.Engine))
	}

	switch r.Params.AdmissionMaxSeverity {
	case "critical", "high", "medium", "low":
	default:
		problems = append(problems, fmt.Sprintf(
			"params.admissionMaxSeverity %q is not critical, high, medium or low",
			r.Params.AdmissionMaxSeverity))
	}

	for name, v := range map[string]int{
		"params.quarantineDays":      r.Params.QuarantineDays,
		"params.deprecateAfterDays":  r.Params.DeprecateAfterDays,
		"params.staleAfterDays":      r.Params.StaleAfterDays,
		"params.deprecatedGraceDays": r.Params.DeprecatedGraceDays,
	} {
		if v < 0 {
			problems = append(problems, name+" cannot be negative")
		}
	}

	if r.Params.MaxTracksPerPackage < 1 {
		problems = append(problems, "params.maxTracksPerPackage must be at least 1")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  %s", ErrInvalid, strings.Join(problems, "\n  "))
	}

	return nil
}

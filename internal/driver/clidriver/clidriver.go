// Package clidriver is forge-register's verb table. The CLI files requests
// and reads state; only the pipeline verbs (apply, evaluate, process,
// publish) write the index, which is how "the pipeline is the only writer"
// stays true: they are what the pipeline runs.
package clidriver

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/registercontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
	"github.com/alexandremahdhaoui/forge-register/pkg/config"
)

// ErrUsage means the invocation itself was wrong, exit 2.
var ErrUsage = errors.New("usage")

// Deps carries everything the driver runs on, so tests inject fakes.
type Deps struct {
	Out      io.Writer
	ReadFile func(string) ([]byte, error)
	Now      func() time.Time
	// Build wires the controller and store for one parsed config.
	Build func(cfg config.Register) (*registercontroller.Controller, storeadapter.Store, error)
}

type Driver struct {
	deps Deps
}

func New(deps Deps) *Driver {
	return &Driver{deps: deps}
}

// Usage is what exit 2 prints.
func Usage() string {
	return strings.TrimSpace(`
forge-register keeps the catalog of adoptable package versions.

  forge-register validate  [--config forge-register.yaml]
  forge-register status    [--config ...]
  forge-register add       [--config ...] <ecosystem>:<package> [--version v] [--track t] --reason "..."  [--requester who]
  forge-register apply     [--config ...]   answer requests, then evaluate every track
  forge-register process   [--config ...]   answer pending requests only
  forge-register evaluate  [--config ...]   evaluate every track only
  forge-register publish   [--config ...] <ecosystem>:<package> <version> --provenance <revision> [--source url]

The CLI files requests and reads state. The index is written only by the
pipeline verbs, which is what the register's pipeline runs.`)
}

func (d *Driver) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: a verb is required", ErrUsage)
	}

	verb := args[0]

	flags := flag.NewFlagSet(verb, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	configPath := flags.String("config", config.DefaultPath, "the register config file")
	version := flags.String("version", "", "an exact version")
	track := flags.String("track", "", "a track prefix")
	reason := flags.String("reason", "", "why - mandatory on requests")
	requester := flags.String("requester", "", "who files the request")
	provenance := flags.String("provenance", "", "the revision that proved an internal package")
	source := flags.String("source", "", "where an internal package comes from")

	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w: %s", ErrUsage, err)
	}

	raw, err := d.deps.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *configPath, err)
	}

	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}

	controller, store, err := d.deps.Build(cfg)
	if err != nil {
		return fmt.Errorf("wiring %s: %w", cfg.Name, err)
	}

	now := d.deps.Now()

	switch verb {
	case "validate":
		return d.describe(cfg)
	case "status":
		return d.status(ctx, store)
	case "add":
		return d.add(ctx, store, flags.Args(), *version, *track, *reason, *requester, now)
	case "apply":
		if err := d.report(ctx, "process", func() (registercontroller.Report, error) {
			return controller.Process(ctx, now)
		}); err != nil {
			return err
		}

		return d.report(ctx, "evaluate", func() (registercontroller.Report, error) {
			return controller.Evaluate(ctx, now)
		})
	case "process":
		return d.report(ctx, "process", func() (registercontroller.Report, error) {
			return controller.Process(ctx, now)
		})
	case "evaluate":
		return d.report(ctx, "evaluate", func() (registercontroller.Report, error) {
			return controller.Evaluate(ctx, now)
		})
	case "publish":
		return d.publish(ctx, controller, flags.Args(), *provenance, *source, now)
	}

	return fmt.Errorf("%w: unknown verb %q", ErrUsage, verb)
}

func (d *Driver) describe(cfg config.Register) error {
	fmt.Fprintf(d.deps.Out, "register %s\n", cfg.Name)
	fmt.Fprintf(d.deps.Out, "  state %s\n", cfg.State.Engine)
	fmt.Fprintf(d.deps.Out, "  quarantine %dd, floor %s, deprecate %dd, stale %dd, grace %dd, tracks<=%d\n",
		cfg.Params.QuarantineDays, cfg.Params.AdmissionMaxSeverity,
		cfg.Params.DeprecateAfterDays, cfg.Params.StaleAfterDays,
		cfg.Params.DeprecatedGraceDays, cfg.Params.MaxTracksPerPackage)

	return nil
}

func (d *Driver) status(ctx context.Context, store storeadapter.Store) error {
	tracks, err := store.Tracks(ctx)
	if err != nil {
		return err
	}

	for _, t := range tracks {
		line := fmt.Sprintf("%s:%s track %s at %s", t.Ecosystem, t.Package, t.Prefix, t.Current)

		if t.Advisory != nil {
			line += fmt.Sprintf("  ADVISORY %s since %s: %s",
				t.Advisory.Severity, t.Advisory.Since.Format("2006-01-02"),
				strings.Join(t.Advisory.VulnIDs, ", "))
		}

		if t.Deprecated != nil {
			line += fmt.Sprintf("  DEPRECATED (%s) since %s",
				t.Deprecated.Reason, t.Deprecated.Since.Format("2006-01-02"))
		}

		fmt.Fprintln(d.deps.Out, line)
	}

	pending, err := store.PendingRequests(ctx)
	if err != nil {
		return err
	}

	for key, r := range pending {
		fmt.Fprintf(d.deps.Out, "pending %s: %s %s:%s %s\n", key, r.Type, r.Ecosystem, r.Package, r.Version)
	}

	fmt.Fprintf(d.deps.Out, "%d tracks, %d pending requests\n", len(tracks), len(pending))

	return nil
}

func (d *Driver) add(ctx context.Context, store storeadapter.Store, args []string, version, track, reason, requester string, now time.Time) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: add needs <ecosystem>:<package>", ErrUsage)
	}

	ecosystem, pkg, ok := strings.Cut(args[0], ":")
	if !ok {
		return fmt.Errorf("%w: add needs <ecosystem>:<package>, got %q", ErrUsage, args[0])
	}

	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: a request with no --reason is a config error, not a warning", ErrUsage)
	}

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: pkg, Ecosystem: ecosystem,
		Track: track, Version: version, Requester: requester, Reason: reason, CreatedAt: now,
	}

	key := registercontroller.RequestKey(request, now)
	if err := store.PutRequest(ctx, key, request); err != nil {
		return err
	}

	fmt.Fprintf(d.deps.Out, "filed %s. the pipeline answers it on its next run.\n", key)

	return nil
}

func (d *Driver) publish(ctx context.Context, controller *registercontroller.Controller, args []string, provenance, source string, now time.Time) error {
	if len(args) != 2 {
		return fmt.Errorf("%w: publish needs <ecosystem>:<package> <version>", ErrUsage)
	}

	ecosystem, pkg, ok := strings.Cut(args[0], ":")
	if !ok {
		return fmt.Errorf("%w: publish needs <ecosystem>:<package>, got %q", ErrUsage, args[0])
	}

	if strings.TrimSpace(provenance) == "" {
		return fmt.Errorf("%w: publish is the proof door; --provenance names the revision that proved it", ErrUsage)
	}

	kv, err := controller.Publish(ctx, ecosystem, pkg, args[1], source, provenance, now)
	if err != nil {
		return err
	}

	fmt.Fprintf(d.deps.Out, "%s %s: %s\n", kv.Verdict.Code, kv.Key, kv.Verdict.Message)

	return nil
}

func (d *Driver) report(ctx context.Context, verb string, run func() (registercontroller.Report, error)) error {
	report, err := run()
	if err != nil {
		return err
	}

	for _, kv := range report.Verdicts {
		fmt.Fprintf(d.deps.Out, "%s %s: %s\n", kv.Verdict.Code, kv.Key, kv.Verdict.Message)
	}

	fmt.Fprintf(d.deps.Out, "%s: %d verdicts, %d adopted\n", verb, len(report.Verdicts), report.Adopted)

	return nil
}

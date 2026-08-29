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
	"regexp"
	"strconv"
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
	// Dispatch files a request into a remote register repo the caller
	// cannot write, via repository_dispatch. Used by add --dispatch.
	Dispatch func(ctx context.Context, repo string, request regtypes.Request) error
	// RemoteHead answers a repo's remote HEAD sha, for the status verb's
	// staleness check on internal tracks. Nil, or an error, skips the
	// check: status must keep working offline.
	RemoteHead func(ctx context.Context, url string) (string, error)
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
  forge-register add       [--config ...] --reason "..." [--version v] [--track t] [--requester who] [--dispatch owner/repo] <ecosystem>:<package>
  forge-register apply     [--config ...]   answer requests, then evaluate every track
  forge-register process   [--config ...]   answer pending requests only
  forge-register evaluate  [--config ...]   evaluate every track only
  forge-register publish   [--config ...] --provenance <revision> [--source url] <ecosystem>:<package> <version>

Every flag comes before the positional arguments. Parsing stops at the first
one that is not a flag, so a --reason after the package is not read and the
failure reads "add needs <ecosystem>:<package>" about a package you did
supply.

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
	dispatch := flags.String("dispatch", "", "owner/name of a register repo to file into remotely, via repository_dispatch (needs GITHUB_TOKEN)")
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
		return d.add(ctx, store, flags.Args(), addOptions{
			Version: *version, Track: *track, Reason: *reason,
			Requester: *requester, Dispatch: *dispatch,
		}, now)
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
	var b strings.Builder

	fmt.Fprintf(&b, "register %s\n", cfg.Name)
	fmt.Fprintf(&b, "  state %s\n", cfg.State.Engine)
	fmt.Fprintf(&b, "  quarantine %dd, floor %s, deprecate %dd, stale %dd, grace %dd, tracks<=%d\n",
		cfg.Params.QuarantineDays, cfg.Params.AdmissionMaxSeverity,
		cfg.Params.DeprecateAfterDays, cfg.Params.StaleAfterDays,
		cfg.Params.DeprecatedGraceDays, cfg.Params.MaxTracksPerPackage)

	if _, err := io.WriteString(d.deps.Out, b.String()); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}

	return nil
}

func (d *Driver) status(ctx context.Context, store storeadapter.Store) error {
	tracks, err := store.Tracks(ctx)
	if err != nil {
		return err
	}

	heads := map[string]string{}

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

		if t.QuietSince != nil {
			line += fmt.Sprintf("  QUIET since %s (no successor; stays current)",
				t.QuietSince.Format("2006-01-02"))
		}

		if head, pinned, stale := d.staleInternal(ctx, t, heads); stale {
			line += fmt.Sprintf("  STALE (pinned %s, repo at %s; a green workspace pipeline republishes)",
				pinned, head)
		}

		if _, err := fmt.Fprintln(d.deps.Out, line); err != nil {
			return fmt.Errorf("writing the report: %w", err)
		}
	}

	pending, err := store.PendingRequests(ctx)
	if err != nil {
		return err
	}

	var b strings.Builder

	for key, r := range pending {
		fmt.Fprintf(&b, "pending %s: %s %s:%s %s\n", key, r.Type, r.Ecosystem, r.Package, r.Version)
	}

	fmt.Fprintf(&b, "%d tracks, %d pending requests\n", len(tracks), len(pending))

	if _, err := io.WriteString(d.deps.Out, b.String()); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}

	return nil
}

// devSHA is the proven sha a dev label carries, e.g.
// v0.1.0-dev.r00000035.g3a25e157e9a9.
var devSHA = regexp.MustCompile(`\.g([0-9a-f]{7,40})$`)

// staleInternal reports whether an internal track's current dev label
// points behind the repo it catalogs. A consumer otherwise learns this
// only when the resolved tuple fails to build - staleness must be
// visible where the operator already looks. Best-effort: no prober, a
// non-dev label or an unreachable remote skip the check silently, so
// status keeps working offline.
func (d *Driver) staleInternal(
	ctx context.Context, t regtypes.Track, heads map[string]string,
) (head, pinned string, stale bool) {
	if d.deps.RemoteHead == nil || t.Ecosystem != "internal" {
		return "", "", false
	}

	match := devSHA.FindStringSubmatch(t.Current)
	if match == nil {
		return "", "", false
	}

	source := t.Source
	if source == "" {
		return "", "", false
	}

	remote, cached := heads[source]
	if !cached {
		resolved, err := d.deps.RemoteHead(ctx, source)
		if err != nil {
			return "", "", false
		}

		remote = resolved
		heads[source] = remote
	}

	pinned = match[1]
	if strings.HasPrefix(remote, pinned) {
		return "", "", false
	}

	head = remote
	if len(head) > 12 {
		head = head[:12]
	}

	return head, pinned, true
}

// addOptions is what one add carries beyond the package.
type addOptions struct {
	Version   string
	Track     string
	Reason    string
	Requester string
	// Dispatch names a remote register repo (owner/name) to file into via
	// repository_dispatch, for a consumer with no write access. Empty
	// files into the local checkout's store.
	Dispatch string
}

// flagsFirstHint names the likely cause when a verb is short of positional
// arguments. Parsing stops at the first argument that is not a flag, so
// `add <package> --reason "..."` reads no package at all and the plain
// requirement then reads like a lie: it names what you supplied. The usage
// text put the flags last for both verbs, so this was the documented order.
func flagsFirstHint(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return ". Every flag comes before the positional arguments, and " +
				strconv.Quote(arg) + " is after one, so nothing past it was read"
		}
	}

	return ""
}

func (d *Driver) add(ctx context.Context, store storeadapter.Store, args []string, opts addOptions, now time.Time) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: add needs <ecosystem>:<package>%s", ErrUsage, flagsFirstHint(args))
	}

	ecosystem, pkg, ok := strings.Cut(args[0], ":")
	if !ok {
		return fmt.Errorf("%w: add needs <ecosystem>:<package>, got %q", ErrUsage, args[0])
	}

	if strings.TrimSpace(opts.Reason) == "" {
		return fmt.Errorf("%w: a request with no --reason is a config error, not a warning", ErrUsage)
	}

	request := regtypes.Request{
		Type: regtypes.RequestAdmission, Package: pkg, Ecosystem: ecosystem,
		Track: opts.Track, Version: opts.Version, Requester: opts.Requester,
		Reason: opts.Reason, CreatedAt: now,
	}

	if opts.Dispatch != "" {
		if err := d.deps.Dispatch(ctx, opts.Dispatch, request); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(d.deps.Out,
			"dispatched %s:%s to %s. its request workflow files it and the pipeline answers.\n",
			ecosystem, pkg, opts.Dispatch); err != nil {
			return fmt.Errorf("writing the report: %w", err)
		}

		return nil
	}

	key := registercontroller.RequestKey(request, now)
	if err := store.PutRequest(ctx, key, request); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(d.deps.Out,
		"filed %s. the pipeline answers it on its next run.\n", key); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}

	return nil
}

func (d *Driver) publish(ctx context.Context, controller *registercontroller.Controller, args []string, provenance, source string, now time.Time) error {
	if len(args) != 2 {
		return fmt.Errorf("%w: publish needs <ecosystem>:<package> <version>%s",
			ErrUsage, flagsFirstHint(args))
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

	if _, err := fmt.Fprintf(d.deps.Out,
		"%s %s: %s\n", kv.Verdict.Code, kv.Key, kv.Verdict.Message); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}

	return nil
}

func (d *Driver) report(ctx context.Context, verb string, run func() (registercontroller.Report, error)) error {
	report, err := run()
	if err != nil {
		return err
	}

	var b strings.Builder

	for _, kv := range report.Verdicts {
		fmt.Fprintf(&b, "%s %s: %s\n", kv.Verdict.Code, kv.Key, kv.Verdict.Message)
	}

	for _, failure := range report.Failed {
		fmt.Fprintf(&b, "feed-failure %s\n", failure)
	}

	// A track that aborted and a track the feed said nothing about are
	// different, and the summary used to report only the first. A run could
	// say "0 feed failures" while three records said the feed could not be
	// reached, which reads as a clean run.
	for _, unmeasured := range report.Unmeasured {
		fmt.Fprintf(&b, "unmeasured %s\n", unmeasured)
	}

	fmt.Fprintf(&b, "%s: %d verdicts, %d adopted, %d aborted, %d unmeasured\n",
		verb, len(report.Verdicts), report.Adopted, len(report.Failed), len(report.Unmeasured))

	if _, err := io.WriteString(d.deps.Out, b.String()); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}

	return nil
}

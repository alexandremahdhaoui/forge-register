package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/dispatchadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/engineadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/osvadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/registryadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/adapter/storeadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/discoverycontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/controller/registercontroller"
	"github.com/alexandremahdhaoui/forge-register/internal/driver/clidriver"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
	"github.com/alexandremahdhaoui/forge-register/pkg/config"
)

var version = "dev"

func main() {
	dispatcher := dispatchadapter.New(http.DefaultClient, "", os.Getenv("GITHUB_TOKEN"))

	driver := clidriver.New(clidriver.Deps{
		Out:      os.Stdout,
		ReadFile: os.ReadFile,
		Now:      time.Now,
		Build:    build,
		Dispatch: func(ctx context.Context, repo string, request regtypes.Request) error {
			return dispatcher.File(ctx, repo, request)
		},
	})

	if err := driver.Run(context.Background(), os.Args[1:]); err != nil {
		if errors.Is(err, clidriver.ErrUsage) {
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, clidriver.Usage())
			os.Exit(2)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(cfg config.Register) (*registercontroller.Controller, storeadapter.Store, error) {
	caller := engineadapter.NewMCPCaller(".", version, os.Stderr)
	store := storeadapter.New(caller, cfg.State.Engine, cfg.State.Spec)

	registries := registryadapter.New(http.DefaultClient, registryadapter.BaseURLs{
		GoProxy: cfg.Registries.GoProxy,
		Crates:  cfg.Registries.Crates,
		PyPI:    cfg.Registries.PyPI,
		NPM:     cfg.Registries.NPM,
	})
	osv := osvadapter.New(http.DefaultClient, cfg.OSV.Base)

	controller := registercontroller.New(
		store,
		discoverycontroller.New(registries, osv),
		regtypes.Params{
			QuarantineDays:       cfg.Params.QuarantineDays,
			AdmissionMaxSeverity: regtypes.Severity(cfg.Params.AdmissionMaxSeverity),
			DeprecateAfterDays:   cfg.Params.DeprecateAfterDays,
			StaleAfterDays:       cfg.Params.StaleAfterDays,
			DeprecatedGraceDays:  cfg.Params.DeprecatedGraceDays,
			MaxTracksPerPackage:  cfg.Params.MaxTracksPerPackage,
		},
	)

	return controller, store, nil
}

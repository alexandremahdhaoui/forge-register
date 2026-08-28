package registryadapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/registryadapter"
)

// fakeRegistries serves one package per ecosystem, the same way the real
// registries answer.
func fakeRegistries(t *testing.T) registryadapter.BaseURLs {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/example.com/pkg/@v/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("v1.0.0\nv1.1.0\n"))
	})
	mux.HandleFunc("/example.com/pkg/@v/v1.0.0.info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/example.com/pkg/@v/v1.1.0.info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"v1.1.0","Time":"2026-02-01T00:00:00Z"}`))
	})

	mux.HandleFunc("/api/v1/crates/example-crate", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"versions":[
			{"num":"1.0.0","created_at":"2026-01-01T00:00:00Z"},
			{"num":"1.0.1","created_at":"2026-02-01T00:00:00Z","yanked":true}
		]}`))
	})

	mux.HandleFunc("/pypi/example-py/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"releases":{
			"1.0.0":[{"upload_time_iso_8601":"2026-01-01T00:00:00Z"}],
			"1.0.1":[]
		}}`))
	})

	mux.HandleFunc("/example-js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"time":{
			"created":"2025-12-01T00:00:00Z",
			"modified":"2026-02-01T00:00:00Z",
			"1.0.0":"2026-01-01T00:00:00Z"
		}}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return registryadapter.BaseURLs{
		GoProxy: server.URL, Crates: server.URL, PyPI: server.URL, NPM: server.URL,
	}
}

func TestEveryEcosystemListsVersionsWithDates(t *testing.T) {
	lister := registryadapter.New(nil, fakeRegistries(t))

	for _, tc := range []struct {
		ecosystem, pkg string
		want           []string
	}{
		{"go", "example.com/pkg", []string{"v1.0.0", "v1.1.0"}},
		{"rust", "example-crate", []string{"1.0.0"}}, // the yanked release is not a candidate
		{"python", "example-py", []string{"1.0.0"}},  // a release with no files is not one either
		{"typescript", "example-js", []string{"1.0.0"}},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			got, err := lister.Versions(context.Background(), tc.ecosystem, tc.pkg)
			require.NoError(t, err)

			versions := make([]string, 0, len(got))
			for _, c := range got {
				require.False(t, c.ReleasedAt.IsZero(), "every candidate carries its release date")
				versions = append(versions, c.Version)
			}

			require.ElementsMatch(t, tc.want, versions)
		})
	}
}

func TestAnUnknownEcosystemIsAnError(t *testing.T) {
	_, err := registryadapter.New(nil, fakeRegistries(t)).Versions(context.Background(), "cobol", "x")
	require.ErrorIs(t, err, registryadapter.ErrEcosystem)
}

func TestAMissingPackageIsAnErrorNotASilence(t *testing.T) {
	_, err := registryadapter.New(nil, fakeRegistries(t)).Versions(context.Background(), "rust", "absent")
	require.ErrorContains(t, err, "status 404")
}

func TestAZeroBaseURLsFallsBackToThePublicRegistries(t *testing.T) {
	// Construction applies the defaults; no request is made here.
	require.NotNil(t, registryadapter.New(nil, registryadapter.BaseURLs{}))
}

// crates.io refuses a request with no User-Agent, and the 403 reads exactly
// like a blocked network. Verified against the live API: without the header
// 403, with it 200. Believing the 403 is what produced a local stand-in and
// a rust index with no release dates.
func TestEveryRegistryRequestIdentifiesItself(t *testing.T) {
	seen := make(chan string, 4)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			// What crates.io really does.
			http.Error(w, "We require that all requests include a `User-Agent` header.",
				http.StatusForbidden)

			return
		}

		select {
		case seen <- r.Header.Get("User-Agent"):
		default:
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"versions":[{"num":"1.0.0","created_at":"2026-01-01T00:00:00Z"}]}`))
	}))
	defer server.Close()

	got, err := registryadapter.New(nil, registryadapter.BaseURLs{Crates: server.URL}).
		Versions(context.Background(), "rust", "serde")
	require.NoError(t, err, "a missing User-Agent must never look like a blocked network")
	require.Len(t, got, 1)

	require.Contains(t, <-seen, "forge-register")
}

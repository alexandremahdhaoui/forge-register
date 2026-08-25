// Copyright 2024 Alexandre Mahdhaoui
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dispatchadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

func request() regtypes.Request {
	return regtypes.Request{
		Type: regtypes.RequestAdmission, Ecosystem: "go", Package: "github.com/x/pkg",
		Reason: "a consumer needs it", Requester: "consumer",
		CreatedAt: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
	}
}

func TestFileSendsTheDispatchShapeTheWorkflowReads(t *testing.T) {
	t.Parallel()

	var gotPath, gotAuth string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	h := New(server.Client(), server.URL, "tok")
	if err := h.File(context.Background(), "org/register", request()); err != nil {
		t.Fatalf("File: %v", err)
	}

	if gotPath != "/repos/org/register/dispatches" || gotAuth != "Bearer tok" {
		t.Errorf("dispatched to %q with %q", gotPath, gotAuth)
	}

	if gotBody["event_type"] != EventType {
		t.Errorf("event_type = %v", gotBody["event_type"])
	}

	pl, _ := gotBody["client_payload"].(map[string]any)
	if pl["package"] != "github.com/x/pkg" || pl["reason"] != "a consumer needs it" || pl["createdAt"] != "2026-08-25T10:00:00Z" {
		t.Errorf("client_payload = %v", pl)
	}
}

func TestFileFailsLoud(t *testing.T) {
	t.Parallel()

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer denied.Close()

	h := New(denied.Client(), denied.URL, "tok")
	if err := h.File(context.Background(), "org/register", request()); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("a denied dispatch must name the status, got %v", err)
	}

	if err := New(denied.Client(), denied.URL, "").File(context.Background(), "org/register", request()); err == nil ||
		!strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("no token must name the fix, got %v", err)
	}

	if err := h.File(context.Background(), "just-a-name", request()); err == nil ||
		!strings.Contains(err.Error(), "owner/name") {
		t.Errorf("a bare repo must fail naming the form, got %v", err)
	}
}

// TestNewDefaultsToTheGitHubAPI: an empty base means api.github.com, and
// a dead network there still names the repo it was dispatching to.
func TestNewDefaultsToTheGitHubAPI(t *testing.T) {
	t.Parallel()

	blocked := &http.Client{Transport: refuseTransport{}}

	err := New(blocked, "", "tok").File(context.Background(), "org/register", request())
	if err == nil || !strings.Contains(err.Error(), "dispatching to org/register") {
		t.Errorf("the default base must be used and the error name the repo, got %v", err)
	}
}

type refuseTransport struct{}

func (refuseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.github.com" {
		return nil, fmt.Errorf("expected api.github.com, got %s", r.URL.Host)
	}

	return nil, fmt.Errorf("no network in this test")
}

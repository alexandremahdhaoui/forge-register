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

// Package dispatchadapter is the remote consumer's request door: it files
// an admission request into a register repo the caller cannot write, by
// sending a GitHub repository_dispatch the register's own workflow turns
// into a stored request. The request stays untrusted input either way -
// it moves the register only by passing the same policy as everything
// else, whoever files it and however it arrives.
package dispatchadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// EventType is the repository_dispatch event the register's request
// workflow listens for.
const EventType = "admission-request"

// HTTP files requests over the GitHub API.
type HTTP struct {
	client *http.Client
	base   string
	token  string
}

// New injects the client, the API base (empty means api.github.com) and
// the token that may dispatch into the register repo.
func New(client *http.Client, base, token string) *HTTP {
	if base == "" {
		base = "https://api.github.com"
	}

	return &HTTP{client: client, base: base, token: token}
}

// payload is the client_payload the request workflow reads. Every field
// is a string on purpose: a dispatch payload crosses two shells before
// the CLI parses it again.
type payload struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Track     string `json:"track,omitempty"`
	Version   string `json:"version,omitempty"`
	Requester string `json:"requester,omitempty"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"createdAt"`
}

// File sends one admission request to repo ("owner/name") as a
// repository_dispatch. GitHub answers 204 on success; anything else is
// the caller's problem to hear about, loud.
func (h *HTTP) File(ctx context.Context, repo string, request regtypes.Request) error {
	if h.token == "" {
		return fmt.Errorf("dispatching to %s: no token; set GITHUB_TOKEN to a token that may dispatch into the register repo", repo)
	}

	if !strings.Contains(repo, "/") {
		return fmt.Errorf("dispatching: %q is not owner/name", repo)
	}

	body, err := json.Marshal(map[string]any{
		"event_type": EventType,
		"client_payload": payload{
			Ecosystem: request.Ecosystem,
			Package:   request.Package,
			Track:     request.Track,
			Version:   request.Version,
			Requester: request.Requester,
			Reason:    request.Reason,
			CreatedAt: request.CreatedAt.UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return fmt.Errorf("encoding the dispatch: %w", err)
	}

	url := h.base + "/repos/" + repo + "/dispatches"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the dispatch to %s: %w", repo, err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+h.token)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatching to %s: %w", repo, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return fmt.Errorf("dispatching to %s: status %d: %s", repo, resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	return nil
}

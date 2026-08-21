// Package storeadapter is the register's typed view of the state transport:
// tracks, requests and verdicts over get, put and list. The store engine is
// forge-ci's ci-state-git with the register kinds named in its spec — this
// repo ships no state engine, and a database later is a new engine behind the
// same transport.
package storeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/alexandremahdhaoui/forge-register/internal/adapter/engineadapter"
	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

const (
	// KindIndex holds one file per package per track.
	KindIndex = "index"
	// KindRequest holds the only door into the register.
	KindRequest = "request"
	// KindVerdict mirrors request keys, plus the pipeline's own evaluations.
	KindVerdict = "verdict"
)

// Store reads and writes register records.
type Store interface {
	Track(ctx context.Context, ecosystem, pkg, prefix string) (regtypes.Track, bool, error)
	PutTrack(ctx context.Context, track regtypes.Track) error
	Tracks(ctx context.Context) ([]regtypes.Track, error)
	TracksOf(ctx context.Context, ecosystem, pkg string) ([]regtypes.Track, error)
	PutRequest(ctx context.Context, key string, request regtypes.Request) error
	PendingRequests(ctx context.Context) (map[string]regtypes.Request, error)
	PutVerdict(ctx context.Context, key string, verdict regtypes.Verdict) error
	Verdict(ctx context.Context, key string) (regtypes.Verdict, bool, error)
}

// MCP implements Store over a state engine spoken through MCP.
type MCP struct {
	caller engineadapter.Caller
	uri    string
	spec   map[string]any
}

var _ Store = (*MCP)(nil)

// New wires the store to one state engine. The register kinds are injected
// into the engine spec, and a nil spec map still travels as an object.
func New(caller engineadapter.Caller, uri string, spec map[string]any) *MCP {
	merged := map[string]any{
		"kinds": []any{KindIndex, KindRequest, KindVerdict},
	}

	for k, v := range spec {
		merged[k] = v
	}

	return &MCP{caller: caller, uri: uri, spec: merged}
}

type getInput struct {
	Kind string         `json:"kind"`
	Key  string         `json:"key,omitempty"`
	Spec map[string]any `json:"spec"`
}

type putInput struct {
	Kind    string         `json:"kind"`
	Key     string         `json:"key"`
	Payload string         `json:"payload"`
	Spec    map[string]any `json:"spec"`
}

type getOutput struct {
	Found   bool   `json:"found"`
	Payload string `json:"payload,omitempty"`
}

type listOutput struct {
	Keys []string `json:"keys"`
}

// TrackKey names a track record: ecosystem, package URL, prefix.
func TrackKey(ecosystem, pkg, prefix string) string {
	return ecosystem + "/" + pkg + "/" + prefix
}

func (s *MCP) Track(ctx context.Context, ecosystem, pkg, prefix string) (regtypes.Track, bool, error) {
	var out getOutput

	in := getInput{Kind: KindIndex, Key: TrackKey(ecosystem, pkg, prefix), Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "get", in, &out); err != nil {
		return regtypes.Track{}, false, fmt.Errorf("reading track %s: %w", in.Key, err)
	}

	if !out.Found {
		return regtypes.Track{}, false, nil
	}

	track, err := trackFromWire([]byte(out.Payload))
	if err != nil {
		return regtypes.Track{}, false, fmt.Errorf("decoding track %s: %w", in.Key, err)
	}

	return track, true, nil
}

func (s *MCP) PutTrack(ctx context.Context, track regtypes.Track) error {
	payload, err := json.Marshal(trackToWire(track))
	if err != nil {
		return fmt.Errorf("encoding track: %w", err)
	}

	key := TrackKey(track.Ecosystem, track.Package, track.Prefix)

	var out getOutput

	in := putInput{Kind: KindIndex, Key: key, Payload: string(payload), Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "put", in, &out); err != nil {
		return fmt.Errorf("writing track %s: %w", key, err)
	}

	return nil
}

func (s *MCP) Tracks(ctx context.Context) ([]regtypes.Track, error) {
	return s.tracksUnder(ctx, "")
}

func (s *MCP) TracksOf(ctx context.Context, ecosystem, pkg string) ([]regtypes.Track, error) {
	return s.tracksUnder(ctx, ecosystem+"/"+pkg)
}

func (s *MCP) tracksUnder(ctx context.Context, prefix string) ([]regtypes.Track, error) {
	var listed listOutput

	in := getInput{Kind: KindIndex, Key: prefix, Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "list", in, &listed); err != nil {
		return nil, fmt.Errorf("listing tracks under %q: %w", prefix, err)
	}

	sort.Strings(listed.Keys)

	tracks := make([]regtypes.Track, 0, len(listed.Keys))

	for _, key := range listed.Keys {
		full := key
		if prefix != "" {
			full = prefix + "/" + key
		}

		var out getOutput

		get := getInput{Kind: KindIndex, Key: full, Spec: s.spec}
		if err := s.caller.Call(ctx, s.uri, "get", get, &out); err != nil {
			return nil, fmt.Errorf("reading track %s: %w", full, err)
		}

		if !out.Found {
			continue
		}

		track, err := trackFromWire([]byte(out.Payload))
		if err != nil {
			return nil, fmt.Errorf("decoding track %s: %w", full, err)
		}

		tracks = append(tracks, track)
	}

	return tracks, nil
}

func (s *MCP) PutRequest(ctx context.Context, key string, request regtypes.Request) error {
	payload, err := json.Marshal(requestToWire(request))
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	var out getOutput

	in := putInput{Kind: KindRequest, Key: key, Payload: string(payload), Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "put", in, &out); err != nil {
		return fmt.Errorf("filing request %s: %w", key, err)
	}

	return nil
}

// PendingRequests returns every request without a verdict at its key. The
// transport has no delete, and does not need one: answering a request is
// writing its verdict.
func (s *MCP) PendingRequests(ctx context.Context) (map[string]regtypes.Request, error) {
	var listed listOutput

	in := getInput{Kind: KindRequest, Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "list", in, &listed); err != nil {
		return nil, fmt.Errorf("listing requests: %w", err)
	}

	pending := map[string]regtypes.Request{}

	for _, key := range listed.Keys {
		if _, found, err := s.Verdict(ctx, key); err != nil {
			return nil, err
		} else if found {
			continue
		}

		var out getOutput

		get := getInput{Kind: KindRequest, Key: key, Spec: s.spec}
		if err := s.caller.Call(ctx, s.uri, "get", get, &out); err != nil {
			return nil, fmt.Errorf("reading request %s: %w", key, err)
		}

		if !out.Found {
			continue
		}

		request, err := requestFromWire([]byte(out.Payload))
		if err != nil {
			return nil, fmt.Errorf("decoding request %s: %w", key, err)
		}

		pending[key] = request
	}

	return pending, nil
}

func (s *MCP) PutVerdict(ctx context.Context, key string, verdict regtypes.Verdict) error {
	payload, err := json.Marshal(verdictToWire(verdict))
	if err != nil {
		return fmt.Errorf("encoding verdict: %w", err)
	}

	var out getOutput

	in := putInput{Kind: KindVerdict, Key: key, Payload: string(payload), Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "put", in, &out); err != nil {
		return fmt.Errorf("recording verdict %s: %w", key, err)
	}

	return nil
}

func (s *MCP) Verdict(ctx context.Context, key string) (regtypes.Verdict, bool, error) {
	var out getOutput

	in := getInput{Kind: KindVerdict, Key: key, Spec: s.spec}
	if err := s.caller.Call(ctx, s.uri, "get", in, &out); err != nil {
		return regtypes.Verdict{}, false, fmt.Errorf("reading verdict %s: %w", key, err)
	}

	if !out.Found {
		return regtypes.Verdict{}, false, nil
	}

	verdict, err := verdictFromWire([]byte(out.Payload))
	if err != nil {
		return regtypes.Verdict{}, false, fmt.Errorf("decoding verdict %s: %w", key, err)
	}

	return verdict, true, nil
}

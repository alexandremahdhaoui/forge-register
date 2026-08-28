package storeadapter

import (
	"encoding/json"
	"time"

	spec "github.com/alexandremahdhaoui/forge-register-spec/pkg/registertypes"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

// A generated wire type is not an internal type. Every record is mapped here,
// explicitly, so a schema change in forge-register-spec is a compile error
// rather than a silent misread.

func trackToWire(t regtypes.Track) spec.Track {
	wire := spec.Track{
		Package:   t.Package,
		Ecosystem: spec.TrackEcosystem(t.Ecosystem),
		Prefix:    t.Prefix,
		Current:   t.Current,
		UpdatedAt: t.UpdatedAt,
	}

	wire.Vulns = vectorToWire(t.Vulns)
	wire.Outcome = spec.Outcome(t.Outcome)
	wire.Reason = orNil(t.Reason)
	wire.Source = orNil(t.Source)
	wire.Provenance = orNil(t.Provenance)
	wire.OsvSnapshot = orNil(t.OSVSnapshot)
	wire.ReleasedAt = orNilTime(t.ReleasedAt)
	wire.AdoptedAt = orNilTime(t.AdoptedAt)

	if t.Advisory != nil {
		wire.Advisory = &spec.Advisory{
			VulnIds:  t.Advisory.VulnIDs,
			Severity: spec.AdvisorySeverity(t.Advisory.Severity),
			Since:    t.Advisory.Since,
		}
	}

	wire.QuietSince = t.QuietSince

	if t.Deprecated != nil {
		wire.Deprecated = &spec.Deprecation{
			Reason: spec.DeprecationReason(t.Deprecated.Reason),
			Since:  t.Deprecated.Since,
		}
	}

	return wire
}

// orNilTime keeps a never-set timestamp out of the file entirely. A zero
// time written as 0001-01-01 reads like a real date to anyone scanning.
func orNilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	return &t
}

func orTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}

	return *t
}

func trackFromWire(payload []byte) (regtypes.Track, error) {
	var wire spec.Track
	if err := json.Unmarshal(payload, &wire); err != nil {
		return regtypes.Track{}, err
	}

	track := regtypes.Track{
		Package:   wire.Package,
		Ecosystem: string(wire.Ecosystem),
		Prefix:    wire.Prefix,
		Current:   wire.Current,
		UpdatedAt: wire.UpdatedAt,
	}

	track.Vulns = vectorFromWire(wire.Vulns)
	track.Outcome = regtypes.Outcome(wire.Outcome)
	track.Reason = orEmptyString(wire.Reason)
	track.Source = orEmptyString(wire.Source)
	track.Provenance = orEmptyString(wire.Provenance)
	track.OSVSnapshot = orEmptyString(wire.OsvSnapshot)
	track.ReleasedAt = orTime(wire.ReleasedAt)
	track.AdoptedAt = orTime(wire.AdoptedAt)

	if wire.Advisory != nil {
		track.Advisory = &regtypes.Advisory{
			VulnIDs:  wire.Advisory.VulnIds,
			Severity: regtypes.Severity(wire.Advisory.Severity),
			Since:    wire.Advisory.Since,
		}
	}

	track.QuietSince = wire.QuietSince

	if wire.Deprecated != nil {
		track.Deprecated = &regtypes.Deprecation{
			Reason: string(wire.Deprecated.Reason),
			Since:  wire.Deprecated.Since,
		}
	}

	return track, nil
}

func requestToWire(r regtypes.Request) spec.Request {
	wire := spec.Request{
		Type:      spec.RequestType(r.Type),
		Package:   r.Package,
		Ecosystem: spec.RequestEcosystem(r.Ecosystem),
		Reason:    r.Reason,
		CreatedAt: r.CreatedAt,
	}

	wire.Track = orNil(r.Track)
	wire.Version = orNil(r.Version)
	wire.Requester = orNil(r.Requester)

	return wire
}

func requestFromWire(payload []byte) (regtypes.Request, error) {
	var wire spec.Request
	if err := json.Unmarshal(payload, &wire); err != nil {
		return regtypes.Request{}, err
	}

	return regtypes.Request{
		Type:      string(wire.Type),
		Package:   wire.Package,
		Ecosystem: string(wire.Ecosystem),
		Track:     orEmptyString(wire.Track),
		Version:   orEmptyString(wire.Version),
		Requester: orEmptyString(wire.Requester),
		Reason:    wire.Reason,
		CreatedAt: wire.CreatedAt,
	}, nil
}

func verdictToWire(v regtypes.Verdict) spec.Verdict {
	wire := spec.Verdict{
		Code:      spec.VerdictCode(v.Code),
		Package:   v.Package,
		DecidedAt: v.DecidedAt,
	}

	if v.Ecosystem != "" {
		eco := spec.VerdictEcosystem(v.Ecosystem)
		wire.Ecosystem = &eco
	}

	wire.Track = orNil(v.Track)
	wire.Requested = orNil(v.Requested)
	wire.Adopted = orNil(v.Adopted)
	wire.OsvSnapshot = orNil(v.OSVSnapshot)
	wire.Message = orNil(v.Message)

	if len(v.Alternatives) > 0 {
		alts := make([]spec.Alternative, 0, len(v.Alternatives))
		for _, a := range v.Alternatives {
			alt := spec.Alternative{Version: a.Version, Vulns: vectorToWire(a.Vulns)}
			if !a.ReleasedAt.IsZero() {
				at := a.ReleasedAt
				alt.ReleasedAt = &at
			}

			alts = append(alts, alt)
		}

		wire.Alternatives = &alts
	}

	return wire
}

func verdictFromWire(payload []byte) (regtypes.Verdict, error) {
	var wire spec.Verdict
	if err := json.Unmarshal(payload, &wire); err != nil {
		return regtypes.Verdict{}, err
	}

	verdict := regtypes.Verdict{
		Code:        string(wire.Code),
		Package:     wire.Package,
		Track:       orEmptyString(wire.Track),
		Requested:   orEmptyString(wire.Requested),
		Adopted:     orEmptyString(wire.Adopted),
		OSVSnapshot: orEmptyString(wire.OsvSnapshot),
		Message:     orEmptyString(wire.Message),
		DecidedAt:   wire.DecidedAt,
	}

	if wire.Ecosystem != nil {
		verdict.Ecosystem = string(*wire.Ecosystem)
	}

	if wire.Alternatives != nil {
		for _, a := range *wire.Alternatives {
			alt := regtypes.Alternative{Version: a.Version, Vulns: vectorFromWire(a.Vulns)}
			if a.ReleasedAt != nil {
				alt.ReleasedAt = *a.ReleasedAt
			}

			verdict.Alternatives = append(verdict.Alternatives, alt)
		}
	}

	return verdict, nil
}

func vectorToWire(v regtypes.Vector) spec.SeverityVector {
	return spec.SeverityVector{Critical: v.Critical, High: v.High, Medium: v.Medium, Low: v.Low}
}

func vectorFromWire(v spec.SeverityVector) regtypes.Vector {
	return regtypes.Vector{Critical: v.Critical, High: v.High, Medium: v.Medium, Low: v.Low}
}

func orNil(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

func orEmptyString(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

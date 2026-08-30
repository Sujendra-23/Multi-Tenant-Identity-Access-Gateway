package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// Signal is one contribution to a request's risk score, kept as a named,
// weighted item so a decision can always be explained rather than just asserted.
type Signal struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Assessment is the risk engine's verdict for a single request.
type Assessment struct {
	Score   int      `json:"score"`
	Signals []Signal `json:"signals"`
	Outcome Outcome  `json:"outcome"`
	Explain string   `json:"explain"`
}

type Outcome string

const (
	OutcomeAllow  Outcome = "allow"
	OutcomeStepUp Outcome = "step_up"
	OutcomeDeny   Outcome = "deny"
)

// Weights. These are deliberately visible constants rather than a learned model:
// a security control that cannot be explained to an auditor is one that will be
// switched off the first time it misfires.
const (
	weightNewDevice       = 25
	weightNewNetwork      = 20
	weightBindingMismatch = 20
	weightRecentFailures  = 15
	weightSensitiveAction = 15
	weightNoMFA           = 10
	weightOffHours        = 5
	weightStaleSession    = 10
)

// RiskEngine scores each request on how far it departs from what this principal
// normally does.
//
// The premise is the zero-trust one: a valid token is evidence, not proof. A
// token presented from a device and network we have never seen for this user,
// during an unusual hour, right after a burst of failed logins, deserves more
// scrutiny than the same token on the user's usual laptop — even though the
// signature is equally valid in both cases.
type RiskEngine struct {
	cache           *redisstore.Client
	denyThreshold   int
	stepUpThreshold int
	retention       time.Duration
}

func NewRiskEngine(cache *redisstore.Client, denyThreshold, stepUpThreshold int) *RiskEngine {
	return &RiskEngine{
		cache:           cache,
		denyThreshold:   denyThreshold,
		stepUpThreshold: stepUpThreshold,
		retention:       90 * 24 * time.Hour,
	}
}

// Input is everything the engine needs about one request.
type Input struct {
	TenantID   uuid.UUID
	UserID     uuid.UUID
	Email      string
	DeviceHash string
	IPHash     string

	// Bindings recorded when the token was issued, for comparison against the
	// fingerprints of the request actually presenting it.
	BoundDevice string
	BoundIP     string

	MFAEnrolled bool
	AMR         []string
	SessionAge  time.Duration
	Resource    string
	Action      string
	Now         time.Time
}

// SensitiveActions attract extra scrutiny regardless of who is asking, because
// they are the ones an attacker needs in order to keep or widen access.
var SensitiveActions = map[string]bool{
	"write":  true,
	"delete": true,
	"revoke": true,
	"export": true,
}

// Assess scores a request and returns both the number and the reasoning.
func (r *RiskEngine) Assess(ctx context.Context, in Input) (*Assessment, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	a := &Assessment{}

	// Behavioural history. These calls also record the current device and
	// network, so the first sighting is the only one that scores.
	if in.DeviceHash != "" {
		known, err := r.cache.KnownDevice(ctx, in.TenantID, in.UserID, in.DeviceHash, r.retention)
		if err != nil {
			return nil, fmt.Errorf("device history: %w", err)
		}
		if !known {
			a.add(Signal{"new_device", weightNewDevice, "no prior request from this device fingerprint"})
		}
	}
	if in.IPHash != "" {
		known, err := r.cache.KnownIP(ctx, in.TenantID, in.UserID, in.IPHash, r.retention)
		if err != nil {
			return nil, fmt.Errorf("network history: %w", err)
		}
		if !known {
			a.add(Signal{"new_network", weightNewNetwork, "request from an unseen network block"})
		}
	}

	// Token binding. A mismatch means the token is being presented from
	// somewhere other than where it was issued, which is what a replayed or
	// exfiltrated token looks like.
	if in.BoundDevice != "" && in.DeviceHash != "" && in.BoundDevice != in.DeviceHash {
		a.add(Signal{"device_binding_mismatch", weightBindingMismatch, "token was issued to a different device"})
	}
	if in.BoundIP != "" && in.IPHash != "" && in.BoundIP != in.IPHash {
		a.add(Signal{"network_binding_mismatch", weightBindingMismatch, "token was issued on a different network"})
	}

	// Recent authentication failures against this identity.
	if in.Email != "" {
		failures, err := r.cache.AuthFailureCount(ctx, in.TenantID, in.Email)
		if err == nil && failures > 0 {
			weight := weightRecentFailures
			if failures > 3 {
				weight *= 2
			}
			a.add(Signal{"recent_auth_failures", weight, fmt.Sprintf("%d failed attempts in the current window", failures)})
		}
	}

	if SensitiveActions[in.Action] {
		a.add(Signal{"sensitive_action", weightSensitiveAction, in.Resource + ":" + in.Action})
	}

	// A password-only session doing something sensitive is the case step-up
	// authentication exists for.
	if !hasAMR(in.AMR, "mfa") {
		weight := weightNoMFA
		if !in.MFAEnrolled {
			weight += 5
		}
		a.add(Signal{"single_factor_session", weight, "session authenticated with a password only"})
	}

	// Long-lived sessions have had more opportunity to be stolen.
	if in.SessionAge > 12*time.Hour {
		a.add(Signal{"stale_session", weightStaleSession,
			fmt.Sprintf("session established %s ago", in.SessionAge.Round(time.Hour))})
	}

	if hour := in.Now.UTC().Hour(); hour < 6 || hour >= 22 {
		a.add(Signal{"off_hours", weightOffHours, fmt.Sprintf("request at %02d:00 UTC", hour)})
	}

	if a.Score > 100 {
		a.Score = 100
	}
	switch {
	case a.Score >= r.denyThreshold:
		a.Outcome = OutcomeDeny
	case a.Score >= r.stepUpThreshold:
		a.Outcome = OutcomeStepUp
	default:
		a.Outcome = OutcomeAllow
	}
	a.Explain = explain(a)
	return a, nil
}

func (a *Assessment) add(s Signal) {
	a.Signals = append(a.Signals, s)
	a.Score += s.Weight
}

// explain renders the signals highest-weight first, so an audit record leads
// with the reason that mattered most.
func explain(a *Assessment) string {
	if len(a.Signals) == 0 {
		return "no elevated risk signals"
	}
	sorted := make([]Signal, len(a.Signals))
	copy(sorted, a.Signals)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Weight > sorted[j].Weight })

	parts := make([]string, 0, len(sorted))
	for _, s := range sorted {
		parts = append(parts, fmt.Sprintf("%s(+%d)", s.Name, s.Weight))
	}
	return strings.Join(parts, ", ")
}

func hasAMR(amr []string, want string) bool {
	for _, v := range amr {
		if v == want {
			return true
		}
	}
	return false
}

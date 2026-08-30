// Package authz answers "may this principal do this thing", and how much the
// gateway should trust the request that asked.
package authz

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// Decision is the outcome of an authorization check, with enough context to
// audit it. Reason is what makes a denial debuggable instead of a mystery.
type Decision struct {
	Allowed   bool
	Reason    string
	Roles     []string
	MatchedBy string
}

// Reasons.
const (
	ReasonExplicitDeny    = "explicit_deny"
	ReasonNoMatchingGrant = "no_matching_grant"
	ReasonGranted         = "granted"
	ReasonTenantMismatch  = "tenant_mismatch"
)

// Evaluator resolves effective permissions and evaluates them.
//
// The cache is keyed by the tenant's policy version, so a permission change
// makes every stale entry unreachable rather than merely expired. That is what
// lets us cache aggressively (permission lookups are on every single request)
// while still revoking in the same instant the change commits.
type Evaluator struct {
	roles   *postgres.RoleRepo
	cache   *redisstore.Client
	metrics *observability.Metrics
	ttl     time.Duration
}

func NewEvaluator(roles *postgres.RoleRepo, cache *redisstore.Client, m *observability.Metrics) *Evaluator {
	return &Evaluator{roles: roles, cache: cache, metrics: m, ttl: 5 * time.Minute}
}

// Load returns the principal's effective permissions, from cache when the
// tenant's policy version matches and from Postgres otherwise.
func (e *Evaluator) Load(ctx context.Context, tenantID uuid.UUID, policyVersion int64, userID uuid.UUID) (*redisstore.CachedPolicy, error) {
	start := time.Now()
	defer func() { e.metrics.AuthzLatency.Observe(time.Since(start).Seconds()) }()

	cached, err := e.cache.GetPolicy(ctx, tenantID, policyVersion, userID)
	if err == nil {
		e.metrics.PolicyCacheOps.WithLabelValues("hit").Inc()
		return cached, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		// A Redis failure must not become an authorization failure: fall
		// through to the source of truth and serve the request correctly but
		// more slowly. Failing closed here would turn a cache outage into a
		// full outage.
		e.metrics.PolicyCacheOps.WithLabelValues("error").Inc()
	} else {
		e.metrics.PolicyCacheOps.WithLabelValues("miss").Inc()
	}

	perms, roleNames, err := e.roles.EffectivePermissions(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	policy := &redisstore.CachedPolicy{Permissions: perms, Roles: roleNames}

	// A cache write failure is not worth failing the request over.
	_ = e.cache.SetPolicy(ctx, tenantID, policyVersion, userID, policy, e.ttl)
	return policy, nil
}

// Evaluate decides whether the permission set covers resource:action.
//
// Two rules, in this order:
//
//  1. Deny by default. An empty permission set authorises nothing; there is no
//     implicit grant anywhere in this function.
//  2. An explicit deny beats any allow, however specific the allow is. This is
//     what lets a tenant grant "billing:*" to a role and then carve out
//     "billing:write" for a subset, without rebuilding the grant list.
func Evaluate(perms []domain.Permission, resource, action string) Decision {
	var matched *domain.Permission

	for i := range perms {
		p := perms[i]
		if !p.Matches(resource, action) {
			continue
		}
		if p.Effect == domain.EffectDeny {
			// Short-circuit: nothing later can overturn an explicit deny.
			return Decision{Allowed: false, Reason: ReasonExplicitDeny, MatchedBy: p.String()}
		}
		if matched == nil || moreSpecific(p, *matched) {
			cp := p
			matched = &cp
		}
	}

	if matched == nil {
		return Decision{Allowed: false, Reason: ReasonNoMatchingGrant}
	}
	return Decision{Allowed: true, Reason: ReasonGranted, MatchedBy: matched.String()}
}

// moreSpecific ranks an exact grant above a wildcard, so the audit record names
// the narrowest rule that actually authorised the request rather than whichever
// one happened to be scanned first.
func moreSpecific(a, b domain.Permission) bool {
	return specificity(a) > specificity(b)
}

func specificity(p domain.Permission) int {
	score := 0
	if p.Resource != "*" {
		score += 2
	}
	if p.Action != "*" {
		score++
	}
	return score
}

// Check loads the principal's policy and evaluates it in one call.
func (e *Evaluator) Check(ctx context.Context, tenantID uuid.UUID, policyVersion int64, userID uuid.UUID, resource, action string) (Decision, error) {
	policy, err := e.Load(ctx, tenantID, policyVersion, userID)
	if err != nil {
		return Decision{Allowed: false, Reason: "evaluation_error"}, err
	}
	d := Evaluate(policy.Permissions, resource, action)
	d.Roles = policy.Roles
	return d, nil
}

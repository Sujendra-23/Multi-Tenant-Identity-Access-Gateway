package authz

import (
	"testing"

	"github.com/sujendra/identity-gateway/internal/domain"
)

func perm(resource, action, effect string) domain.Permission {
	return domain.Permission{Resource: resource, Action: action, Effect: effect}
}

func TestEvaluate_DenyByDefault(t *testing.T) {
	d := Evaluate(nil, "billing", "read")
	if d.Allowed {
		t.Fatal("empty permission set must not authorise anything")
	}
	if d.Reason != ReasonNoMatchingGrant {
		t.Fatalf("reason = %q, want %q", d.Reason, ReasonNoMatchingGrant)
	}
}

func TestEvaluate_ExplicitAllow(t *testing.T) {
	perms := []domain.Permission{perm("billing", "read", domain.EffectAllow)}
	d := Evaluate(perms, "billing", "read")
	if !d.Allowed {
		t.Fatal("exact allow grant should authorise")
	}
}

func TestEvaluate_WildcardResourceAndAction(t *testing.T) {
	cases := []struct {
		name  string
		grant domain.Permission
	}{
		{"wildcard action", perm("billing", "*", domain.EffectAllow)},
		{"wildcard resource", perm("*", "read", domain.EffectAllow)},
		{"full wildcard", perm("*", "*", domain.EffectAllow)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate([]domain.Permission{tc.grant}, "billing", "read")
			if !d.Allowed {
				t.Fatalf("grant %+v should cover billing:read", tc.grant)
			}
		})
	}
}

// TestEvaluate_ExplicitDenyBeatsWildcardAllow is the central RBAC invariant: a
// tenant granting "billing:*" and then denying "billing:write" specifically
// must end up unable to write, no matter which order the two grants are stored
// or scanned in.
func TestEvaluate_ExplicitDenyBeatsWildcardAllow(t *testing.T) {
	perms := []domain.Permission{
		perm("billing", "*", domain.EffectAllow),
		perm("billing", "write", domain.EffectDeny),
	}
	d := Evaluate(perms, "billing", "write")
	if d.Allowed {
		t.Fatal("explicit deny must beat a broader allow")
	}
	if d.Reason != ReasonExplicitDeny {
		t.Fatalf("reason = %q, want %q", d.Reason, ReasonExplicitDeny)
	}

	// The wildcard allow must still cover every other action.
	d2 := Evaluate(perms, "billing", "read")
	if !d2.Allowed {
		t.Fatal("the deny on billing:write must not affect billing:read")
	}
}

func TestEvaluate_DenyOrderIndependent(t *testing.T) {
	// Same two grants, reversed order: the outcome must not depend on scan
	// order, since a real permission set comes back from a database query with
	// no guaranteed ordering.
	perms := []domain.Permission{
		perm("billing", "write", domain.EffectDeny),
		perm("billing", "*", domain.EffectAllow),
	}
	d := Evaluate(perms, "billing", "write")
	if d.Allowed {
		t.Fatal("explicit deny must beat allow regardless of slice order")
	}
}

func TestEvaluate_UnrelatedPermissionDoesNotMatch(t *testing.T) {
	perms := []domain.Permission{perm("users", "read", domain.EffectAllow)}
	d := Evaluate(perms, "billing", "read")
	if d.Allowed {
		t.Fatal("a grant for a different resource must not authorise this one")
	}
}

func TestEvaluate_MatchedByReportsNarrowestGrant(t *testing.T) {
	perms := []domain.Permission{
		perm("*", "*", domain.EffectAllow),
		perm("billing", "read", domain.EffectAllow),
	}
	d := Evaluate(perms, "billing", "read")
	if !d.Allowed {
		t.Fatal("should be allowed")
	}
	if d.MatchedBy != "billing:read" {
		t.Fatalf("MatchedBy = %q, want the narrowest matching grant %q", d.MatchedBy, "billing:read")
	}
}

func TestPermissionMatches(t *testing.T) {
	cases := []struct {
		grant            domain.Permission
		resource, action string
		want             bool
	}{
		{perm("billing", "read", ""), "billing", "read", true},
		{perm("billing", "read", ""), "billing", "write", false},
		{perm("billing", "*", ""), "billing", "write", true},
		{perm("*", "read", ""), "users", "read", true},
		{perm("*", "*", ""), "anything", "goes", true},
		{perm("billing", "read", ""), "users", "read", false},
	}
	for _, tc := range cases {
		got := tc.grant.Matches(tc.resource, tc.action)
		if got != tc.want {
			t.Errorf("Permission%+v.Matches(%q,%q) = %v, want %v", tc.grant, tc.resource, tc.action, got, tc.want)
		}
	}
}

func TestParsePermission(t *testing.T) {
	p, err := domain.ParsePermission("billing:read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Resource != "billing" || p.Action != "read" || p.Effect != domain.EffectAllow {
		t.Fatalf("got %+v", p)
	}

	if _, err := domain.ParsePermission("nocolonhere"); err == nil {
		t.Fatal("expected an error for a permission string without a colon")
	}
	if _, err := domain.ParsePermission(":read"); err == nil {
		t.Fatal("expected an error for an empty resource")
	}
}

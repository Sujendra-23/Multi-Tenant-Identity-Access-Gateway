package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash does not look like a PHC argon2id string: %s", hash)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("the-real-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("not-the-real-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("wrong password verified successfully")
	}
}

func TestHashPassword_UniqueSaltPerCall(t *testing.T) {
	h1, err := HashPassword("same input")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword("same input")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
	// Both must still verify independently.
	if ok, _ := VerifyPassword("same input", h1); !ok {
		t.Fatal("h1 did not verify")
	}
	if ok, _ := VerifyPassword("same input", h2); !ok {
		t.Fatal("h2 did not verify")
	}
}

func TestVerifyPassword_RejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash-at-all",
		"$argon2id$v=19$m=19456,t=3,p=1$badbase64!!!$alsobad",
		"$bcrypt$v=1$whatever$whatever",
	}
	for _, c := range cases {
		if _, err := VerifyPassword("anything", c); err == nil {
			t.Errorf("expected an error verifying against malformed hash %q", c)
		}
	}
}

func TestBurnTimingBudget_DoesNotPanic(t *testing.T) {
	// Just needs to run without panicking; the timing property itself is not
	// something a unit test can meaningfully assert.
	BurnTimingBudget("whatever")
}

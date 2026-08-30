package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow the OWASP guidance of the second
// configuration: 19 MiB of memory with three iterations. Memory hardness is the
// point — it is what makes a GPU or ASIC attack expensive in a way that raising
// iteration count alone does not.
const (
	argonTime    = 3
	argonMemory  = 19 * 1024 // KiB
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	ErrInvalidHashFormat = errors.New("password hash is not in the expected format")
	ErrIncompatibleAlgo  = errors.New("password hash uses an unsupported algorithm")
)

// HashPassword produces a PHC-format argon2id string. The format embeds the
// parameters, so raising the cost later does not invalidate existing hashes:
// each one is verified with the parameters it was created under, and can be
// upgraded on the user's next successful login.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	parallelism := uint8(min(runtime.NumCPU(), 4))
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, parallelism, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against a PHC-format hash.
//
// The comparison is constant time. A byte-by-byte comparison that returns early
// leaks how much of the digest matched, which over many attempts is enough to
// reconstruct it.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return false, ErrInvalidHashFormat
	}
	if parts[1] != "argon2id" {
		return false, ErrIncompatibleAlgo
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHashFormat
	}
	if version != argon2.Version {
		return false, ErrIncompatibleAlgo
	}

	var memory, time uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism); err != nil {
		return false, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHashFormat
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when a login names a user that does not exist.
//
// Without it, a missing user returns in microseconds while a real one takes the
// full argon2 cost, and that timing difference is a free user-enumeration
// oracle. Doing the same work either way removes the signal.
var dummyHash string

func init() {
	h, err := HashPassword("this password is never valid for any account")
	if err != nil {
		panic("auth: cannot initialise dummy password hash: " + err.Error())
	}
	dummyHash = h
}

// BurnTimingBudget performs the same work a real verification would, so that a
// failed lookup is indistinguishable from a wrong password.
func BurnTimingBudget(password string) {
	_, _ = VerifyPassword(password, dummyHash)
}

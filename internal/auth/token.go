package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
)

// Claims is the gateway's access-token payload.
//
// It carries just enough to make the common case cheap — tenant, subject,
// session and the policy version — and deliberately does not carry the
// permission set itself. Embedding permissions would make a token a standalone
// grant that stays valid until it expires, which is exactly the property zero
// trust is trying to remove.
type Claims struct {
	jwt.RegisteredClaims

	TenantID      uuid.UUID `json:"tid"`
	TenantSlug    string    `json:"tsl"`
	SessionID     uuid.UUID `json:"sid"`
	Email         string    `json:"email"`
	PolicyVersion int64     `json:"pv"`

	// Roles are informational, for downstream services that want a cheap hint.
	// The gateway never authorises from this field; it resolves permissions from
	// the store or the version-keyed cache.
	Roles []string `json:"roles,omitempty"`

	// AMR records how the principal authenticated ("pwd", "mfa"). Step-up
	// decisions read it to tell a password-only session from a re-verified one.
	AMR []string `json:"amr,omitempty"`

	// Binding fingerprints. A token that is presented from a different device or
	// network than it was issued to is not automatically rejected, but it is
	// scored as higher risk. Hashes, not raw values, so a decoded token does not
	// disclose the holder's address.
	DeviceBinding string `json:"dbn,omitempty"`
	IPBinding     string `json:"ibn,omitempty"`
}

// TokenPair is what a login or refresh returns.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionID    uuid.UUID `json:"session_id"`
}

type TokenIssuer struct {
	keyring  *Keyring
	issuer   string
	audience string
	ttl      time.Duration
}

func NewTokenIssuer(keyring *Keyring, issuer, audience string, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{keyring: keyring, issuer: issuer, audience: audience, ttl: ttl}
}

// Mint signs an access token with the currently active key.
func (t *TokenIssuer) Mint(c Claims) (string, time.Time, error) {
	key, err := t.keyring.Active()
	if err != nil {
		return "", time.Time{}, err
	}

	now := time.Now()
	expires := now.Add(t.ttl)

	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    t.issuer,
		Subject:   c.Subject,
		Audience:  jwt.ClaimStrings{t.audience},
		ExpiresAt: jwt.NewNumericDate(expires),
		NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)), // tolerate modest clock skew
		IssuedAt:  jwt.NewNumericDate(now),
		// A unique jti is what makes an individual token revocable: the
		// denylist holds jtis, not whole sessions.
		ID: uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	token.Header["kid"] = key.KID

	signed, err := token.SignedString(key.Private)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, expires, nil
}

// Parse verifies a token's signature and registered claims.
//
// The algorithm is pinned to EdDSA. Accepting whatever the header asks for is
// the classic JWT vulnerability: an attacker flips alg to "none", or to HS256
// and signs with the public key as the HMAC secret. Pinning removes both.
func (t *TokenIssuer) Parse(raw string) (*Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no key id")
		}
		return t.keyring.PublicKey(kid)
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(t.issuer),
		jwt.WithAudience(t.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidCredential, err)
	}
	return &claims, nil
}

// NewRefreshToken returns 256 bits of CSPRNG output.
//
// Refresh tokens are opaque rather than JWTs on purpose. A JWT refresh token
// would be independently verifiable, which sounds convenient but means it cannot
// be revoked without a lookup anyway; making it a reference to server-side state
// is more honest and enables single-use rotation.
func NewRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DeviceFingerprint derives a stable per-client identifier from headers a
// browser sends on every request.
//
// This is a weak signal by design: it is trivially forgeable by an attacker who
// controls the client. It is not used as an authentication factor, only as a
// risk input — a token arriving from a fingerprint we have never seen for this
// user is worth scoring, not worth rejecting outright.
func DeviceFingerprint(userAgent, acceptLanguage, clientHint string) string {
	h := sha256.New()
	h.Write([]byte(userAgent))
	h.Write([]byte{0x1f})
	h.Write([]byte(acceptLanguage))
	h.Write([]byte{0x1f})
	h.Write([]byte(clientHint))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// NetworkFingerprint hashes the client's network rather than its exact address.
//
// It truncates IPv4 to the /24 and IPv6 to the /48 before hashing, so a client
// on a mobile network that reassigns addresses within a block does not look like
// a new location on every request. Hashing means we hold a comparison key, not
// an address history.
func NetworkFingerprint(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	var masked net.IP
	if v4 := ip.To4(); v4 != nil {
		masked = v4.Mask(net.CIDRMask(24, 32))
	} else {
		masked = ip.Mask(net.CIDRMask(48, 128))
	}
	sum := sha256.Sum256([]byte(masked.String()))
	return hex.EncodeToString(sum[:])[:32]
}

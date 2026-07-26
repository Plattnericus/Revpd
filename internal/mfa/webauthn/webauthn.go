// Package webauthn implements the server half of WebAuthn level 2, limited to
// what a second factor needs: registration and assertion with ES256 or RS256.
//
// Written out rather than pulled in as a dependency. The verification steps
// are the security-relevant part of the protocol and are worth being able to
// read; the whole thing is a few hundred lines and drags in no CBOR or COSE
// library beyond what is needed here.
//
// Follows W3C WebAuthn level 2, sections 7.1 (registration) and 7.2
// (authentication). Step numbers in comments refer to those.
package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrChallenge  = errors.New("challenge does not match")
	ErrOrigin     = errors.New("origin does not match")
	ErrRPID       = errors.New("relying party does not match")
	ErrNotPresent = errors.New("the user did not confirm presence")
	ErrSignature  = errors.New("signature is not valid")
	ErrCloned     = errors.New("authenticator counter went backwards, it may be cloned")
	ErrMalformed  = errors.New("malformed webauthn data")
)

// Config identifies this gateway to the authenticator.
type Config struct {
	// RPID is the hostname, without scheme or port. A passkey is bound to it,
	// so changing the hostname invalidates every registration.
	RPID string

	// Origin is the full origin the browser reports, scheme and port included.
	Origin string

	// DisplayName appears in the operating system's passkey prompt.
	DisplayName string
}

/* ------------------------------------------------------------ challenge --- */

// Challenge is a pending registration or assertion.
type Challenge struct {
	Value     []byte
	UserID    int64
	ExpiresAt time.Time
}

func NewChallenge(userID int64, ttl time.Duration) (*Challenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	return &Challenge{Value: b, UserID: userID, ExpiresAt: time.Now().Add(ttl)}, nil
}

func (c *Challenge) Expired() bool { return time.Now().After(c.ExpiresAt) }

/* --------------------------------------------------------- registration --- */

// RegistrationOptions is what the browser passes to navigator.credentials.create.
type RegistrationOptions struct {
	Challenge              string           `json:"challenge"`
	RP                     rpEntity         `json:"rp"`
	User                   userEntity       `json:"user"`
	PubKeyCredParams       []credParam      `json:"pubKeyCredParams"`
	Timeout                int              `json:"timeout"`
	AuthenticatorSelection authSelection    `json:"authenticatorSelection"`
	Attestation            string           `json:"attestation"`
	ExcludeCredentials     []credDescriptor `json:"excludeCredentials"`
}

type rpEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type credParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type authSelection struct {
	UserVerification   string `json:"userVerification"`
	ResidentKey        string `json:"residentKey"`
	RequireResidentKey bool   `json:"requireResidentKey"`
}

type credDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// COSE algorithm identifiers. ES256 first: it is what every platform
// authenticator produces, and RS256 covers older security keys.
const (
	algES256 = -7
	algRS256 = -257
)

// BeginRegistration builds the options for a new passkey.
func (c Config) BeginRegistration(ch *Challenge, userID int64, username, display string, existing [][]byte) RegistrationOptions {
	exclude := make([]credDescriptor, 0, len(existing))
	for _, id := range existing {
		exclude = append(exclude, credDescriptor{Type: "public-key", ID: b64(id)})
	}

	uid := make([]byte, 8)
	binary.BigEndian.PutUint64(uid, uint64(userID))

	return RegistrationOptions{
		Challenge: b64(ch.Value),
		RP:        rpEntity{ID: c.RPID, Name: c.DisplayName},
		User:      userEntity{ID: b64(uid), Name: username, DisplayName: display},
		PubKeyCredParams: []credParam{
			{Type: "public-key", Alg: algES256},
			{Type: "public-key", Alg: algRS256},
		},
		Timeout: 120_000,
		AuthenticatorSelection: authSelection{
			// Ask for verification but do not insist: a security key without a
			// PIN is still a far better second factor than none.
			UserVerification:   "preferred",
			ResidentKey:        "preferred",
			RequireResidentKey: false,
		},
		Attestation:        "none", // we do not need to know the make and model
		ExcludeCredentials: exclude,
	}
}

// RegistrationResponse is what the browser sends back.
type RegistrationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

// Credential is a verified registration, ready to store.
type Credential struct {
	ID        []byte
	PublicKey []byte // COSE key, as it came off the authenticator
	SignCount uint32
}

// FinishRegistration verifies a registration and returns the credential.
func (c Config) FinishRegistration(ch *Challenge, resp RegistrationResponse) (*Credential, error) {
	if ch == nil || ch.Expired() {
		return nil, ErrChallenge
	}

	clientData, err := unb64(resp.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: client data: %v", ErrMalformed, err)
	}
	if err := c.checkClientData(clientData, ch.Value, "webauthn.create"); err != nil {
		return nil, err
	}

	attestation, err := unb64(resp.Response.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation: %v", ErrMalformed, err)
	}

	authData, err := extractAuthData(attestation)
	if err != nil {
		return nil, err
	}

	parsed, err := parseAuthData(authData)
	if err != nil {
		return nil, err
	}
	if err := c.checkAuthData(parsed); err != nil {
		return nil, err
	}
	if parsed.CredentialID == nil || parsed.PublicKey == nil {
		return nil, fmt.Errorf("%w: registration carries no credential", ErrMalformed)
	}

	// The public key must be one we can actually verify with later.
	if _, err := parseCOSEKey(parsed.PublicKey); err != nil {
		return nil, err
	}

	return &Credential{
		ID:        parsed.CredentialID,
		PublicKey: parsed.PublicKey,
		SignCount: parsed.SignCount,
	}, nil
}

/* ------------------------------------------------------------ assertion --- */

// AssertionOptions is what the browser passes to navigator.credentials.get.
type AssertionOptions struct {
	Challenge        string           `json:"challenge"`
	Timeout          int              `json:"timeout"`
	RPID             string           `json:"rpId"`
	AllowCredentials []credDescriptor `json:"allowCredentials"`
	UserVerification string           `json:"userVerification"`
}

// BeginAssertion builds the options for a login.
//
// An empty allow-list means a usernameless login: the browser offers whatever
// resident key it holds for this site.
func (c Config) BeginAssertion(ch *Challenge, allowed [][]byte) AssertionOptions {
	allow := make([]credDescriptor, 0, len(allowed))
	for _, id := range allowed {
		allow = append(allow, credDescriptor{Type: "public-key", ID: b64(id)})
	}

	return AssertionOptions{
		Challenge:        b64(ch.Value),
		Timeout:          120_000,
		RPID:             c.RPID,
		AllowCredentials: allow,
		UserVerification: "preferred",
	}
}

// AssertionResponse is what the browser sends back.
type AssertionResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

// FinishAssertion verifies a login against a stored public key and returns the
// authenticator's new counter.
func (c Config) FinishAssertion(ch *Challenge, resp AssertionResponse, publicKey []byte, storedCount uint32) (uint32, error) {
	if ch == nil || ch.Expired() {
		return 0, ErrChallenge
	}

	clientData, err := unb64(resp.Response.ClientDataJSON)
	if err != nil {
		return 0, fmt.Errorf("%w: client data: %v", ErrMalformed, err)
	}
	if err := c.checkClientData(clientData, ch.Value, "webauthn.get"); err != nil {
		return 0, err
	}

	authData, err := unb64(resp.Response.AuthenticatorData)
	if err != nil {
		return 0, fmt.Errorf("%w: authenticator data: %v", ErrMalformed, err)
	}

	parsed, err := parseAuthData(authData)
	if err != nil {
		return 0, err
	}
	if err := c.checkAuthData(parsed); err != nil {
		return 0, err
	}

	sig, err := unb64(resp.Response.Signature)
	if err != nil {
		return 0, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}

	// Step 7.2.20: the signature covers authenticatorData || SHA-256(clientDataJSON).
	digest := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), digest[:]...)

	key, err := parseCOSEKey(publicKey)
	if err != nil {
		return 0, err
	}
	if err := verify(key, signed, sig); err != nil {
		return 0, err
	}

	// Step 7.2.21: a counter that fails to advance suggests a cloned
	// authenticator. Zero on both sides means the authenticator does not keep
	// one at all, which is allowed.
	if storedCount != 0 || parsed.SignCount != 0 {
		if parsed.SignCount <= storedCount {
			return 0, ErrCloned
		}
	}

	return parsed.SignCount, nil
}

/* --------------------------------------------------------- verification --- */

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// checkClientData covers steps 7.1.7 through 7.1.10 and their assertion twins.
func (c Config) checkClientData(raw, challenge []byte, wantType string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("%w: client data is not json: %v", ErrMalformed, err)
	}

	if cd.Type != wantType {
		return fmt.Errorf("%w: type is %q, want %q", ErrMalformed, cd.Type, wantType)
	}

	got, err := unb64(cd.Challenge)
	if err != nil {
		return fmt.Errorf("%w: challenge is not base64url: %v", ErrMalformed, err)
	}
	// Constant time, so a mismatch cannot be probed byte by byte.
	if subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrChallenge
	}

	if cd.Origin != c.Origin {
		return fmt.Errorf("%w: %q, want %q", ErrOrigin, cd.Origin, c.Origin)
	}
	return nil
}

// authData is the parsed authenticator data structure.
type authData struct {
	RPIDHash     []byte
	Flags        byte
	SignCount    uint32
	CredentialID []byte
	PublicKey    []byte
}

// Authenticator data flags.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttestedData = 0x40
)

func parseAuthData(b []byte) (*authData, error) {
	// rpIdHash(32) flags(1) signCount(4) is the fixed part.
	if len(b) < 37 {
		return nil, fmt.Errorf("%w: authenticator data is %d bytes", ErrMalformed, len(b))
	}

	a := &authData{
		RPIDHash:  b[:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:37]),
	}

	if a.Flags&flagAttestedData == 0 {
		return a, nil
	}

	// aaguid(16) credentialIdLength(2) credentialId publicKey
	rest := b[37:]
	if len(rest) < 18 {
		return nil, fmt.Errorf("%w: attested data is truncated", ErrMalformed)
	}

	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	if idLen <= 0 || idLen > 1023 || len(rest) < 18+idLen {
		return nil, fmt.Errorf("%w: credential id length %d", ErrMalformed, idLen)
	}

	a.CredentialID = rest[18 : 18+idLen]
	a.PublicKey = rest[18+idLen:]
	return a, nil
}

// checkAuthData covers steps 7.1.13 and 7.1.14.
func (c Config) checkAuthData(a *authData) error {
	want := sha256.Sum256([]byte(c.RPID))
	if subtle.ConstantTimeCompare(a.RPIDHash, want[:]) != 1 {
		return ErrRPID
	}

	// Presence is mandatory: it is what makes a passkey a deliberate act
	// rather than something a page can trigger silently.
	if a.Flags&flagUserPresent == 0 {
		return ErrNotPresent
	}
	return nil
}

/* ---------------------------------------------------------------- keys --- */

// publicKey is whatever we managed to decode from the COSE structure.
type publicKey struct {
	ecdsa *ecdsa.PublicKey
	rsa   *rsa.PublicKey
}

// parseCOSEKey decodes the subset of CBOR that a COSE_Key uses.
//
// Only ES256 and RS256 are accepted. Anything else is refused rather than
// guessed at — an unverifiable key stored now is a login that fails later.
func parseCOSEKey(b []byte) (*publicKey, error) {
	m, err := decodeCBORMap(b)
	if err != nil {
		return nil, fmt.Errorf("%w: cose key: %v", ErrMalformed, err)
	}

	// COSE labels are negative for key material and positive for metadata.
	// The decoder produces int64 keys, so index with int64 throughout.
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)

	switch {
	case kty == 2 && alg == algES256: // EC2 over P-256
		x, okX := m[int64(-2)].([]byte)
		y, okY := m[int64(-3)].([]byte)
		if !okX || !okY || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: ec2 key has bad coordinates", ErrMalformed)
		}
		return &publicKey{ecdsa: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}}, nil

	case kty == 3 && alg == algRS256: // RSA
		n, okN := m[int64(-1)].([]byte)
		e, okE := m[int64(-2)].([]byte)
		if !okN || !okE || len(n) == 0 || len(e) == 0 {
			return nil, fmt.Errorf("%w: rsa key is incomplete", ErrMalformed)
		}
		exp := 0
		for _, x := range e {
			exp = exp<<8 | int(x)
		}
		return &publicKey{rsa: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}}, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type %d algorithm %d", ErrMalformed, kty, alg)
	}
}

func verify(k *publicKey, signed, sig []byte) error {
	digest := sha256.Sum256(signed)

	switch {
	case k.ecdsa != nil:
		if !ecdsa.VerifyASN1(k.ecdsa, digest[:], sig) {
			return ErrSignature
		}
	case k.rsa != nil:
		if err := rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest[:], sig); err != nil {
			return ErrSignature
		}
	default:
		return ErrSignature
	}
	return nil
}

/* ---------------------------------------------------------------- b64 --- */

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeB64 decodes a base64url value the browser produced, padded or not.
func DecodeB64(s string) ([]byte, error) { return unb64(s) }

// unb64 accepts both padded and unpadded base64url; browsers differ.
func unb64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

/*
   A software authenticator, so the verification path can be exercised without
   a security key. It produces exactly what a real one does: a COSE key, the
   authenticator data structure, and an ES256 signature over the concatenation
   the spec requires.
*/

type fakeAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

func newAuthenticator(t *testing.T) *fakeAuthenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	id := make([]byte, 32)
	rand.Read(id)

	return &fakeAuthenticator{key: key, credID: id, count: 0}
}

// coseKey encodes the public key the way an authenticator does.
func (a *fakeAuthenticator) coseKey() []byte {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))

	// map(5) { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
	out := []byte{0xA5}
	out = append(out, 0x01, 0x02)       // kty: EC2
	out = append(out, 0x03, 0x26)       // alg: ES256 (-7)
	out = append(out, 0x20, 0x01)       // crv: P-256 (label -1)
	out = append(out, 0x21, 0x58, 0x20) // label -2, bytes(32)
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20) // label -3, bytes(32)
	out = append(out, y...)
	return out
}

func (a *fakeAuthenticator) authData(rpID string, flags byte, withCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))

	out := append([]byte{}, h[:]...)
	out = append(out, flags)

	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, a.count)
	out = append(out, count...)

	if withCred {
		out = append(out, make([]byte, 16)...) // aaguid
		idLen := make([]byte, 2)
		binary.BigEndian.PutUint16(idLen, uint16(len(a.credID)))
		out = append(out, idLen...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

// attestationObject wraps authData with attestation format "none".
func (a *fakeAuthenticator) attestationObject(rpID string) []byte {
	data := a.authData(rpID, flagUserPresent|flagUserVerified|flagAttestedData, true)

	// map(3) { "fmt": "none", "attStmt": {}, "authData": bytes }
	out := []byte{0xA3}
	out = append(out, 0x63, 'f', 'm', 't')
	out = append(out, 0x64, 'n', 'o', 'n', 'e')
	out = append(out, 0x67, 'a', 't', 't', 'S', 't', 'm', 't')
	out = append(out, 0xA0) // empty map
	out = append(out, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')
	out = append(out, cborByteHeader(len(data))...)
	out = append(out, data...)
	return out
}

func cborByteHeader(n int) []byte {
	switch {
	case n < 24:
		return []byte{byte(0x40 | n)}
	case n < 256:
		return []byte{0x58, byte(n)}
	default:
		return []byte{0x59, byte(n >> 8), byte(n)}
	}
}

func (a *fakeAuthenticator) clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return raw
}

// sign produces the assertion signature over authData || SHA-256(clientData).
func (a *fakeAuthenticator) sign(t *testing.T, authData, clientData []byte) []byte {
	t.Helper()

	digest := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), digest[:]...)
	sum := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

/* ---------------------------------------------------------------- setup --- */

var cfg = Config{RPID: "gw.example.com", Origin: "https://gw.example.com:8443", DisplayName: "Revpd"}

func challenge(t *testing.T) *Challenge {
	t.Helper()
	ch, err := NewChallenge(1, time.Minute)
	if err != nil {
		t.Fatalf("new challenge: %v", err)
	}
	return ch
}

func register(t *testing.T, a *fakeAuthenticator, ch *Challenge) (*Credential, error) {
	t.Helper()

	var resp RegistrationResponse
	resp.Type = "public-key"
	resp.Response.ClientDataJSON = b64(a.clientDataJSON(t, "webauthn.create", b64(ch.Value), cfg.Origin))
	resp.Response.AttestationObject = b64(a.attestationObject(cfg.RPID))

	return cfg.FinishRegistration(ch, resp)
}

func assert(t *testing.T, a *fakeAuthenticator, ch *Challenge, cred *Credential, stored uint32) (uint32, error) {
	t.Helper()

	authData := a.authData(cfg.RPID, flagUserPresent|flagUserVerified, false)
	clientData := a.clientDataJSON(t, "webauthn.get", b64(ch.Value), cfg.Origin)

	var resp AssertionResponse
	resp.Type = "public-key"
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	return cfg.FinishAssertion(ch, resp, cred.PublicKey, stored)
}

/* -------------------------------------------------------------- happy --- */

func TestRegisterThenAuthenticate(t *testing.T) {
	a := newAuthenticator(t)

	cred, err := register(t, a, challenge(t))
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	if string(cred.ID) != string(a.credID) {
		t.Fatal("the credential id does not round trip")
	}

	a.count = 1
	count, err := assert(t, a, challenge(t), cred, 0)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	if count != 1 {
		t.Fatalf("sign count = %d, want 1", count)
	}
}

func TestOptionsAreWellFormed(t *testing.T) {
	ch := challenge(t)

	reg := cfg.BeginRegistration(ch, 7, "felix", "Felix", [][]byte{{1, 2, 3}})
	if reg.RP.ID != cfg.RPID {
		t.Fatalf("rp id = %q", reg.RP.ID)
	}
	if len(reg.PubKeyCredParams) != 2 {
		t.Fatalf("offered %d algorithms, want ES256 and RS256", len(reg.PubKeyCredParams))
	}
	if reg.Attestation != "none" {
		t.Fatalf("attestation = %q, want none", reg.Attestation)
	}
	if len(reg.ExcludeCredentials) != 1 {
		t.Fatal("existing credentials were not excluded, the same key could register twice")
	}

	ass := cfg.BeginAssertion(ch, nil)
	if ass.RPID != cfg.RPID {
		t.Fatalf("assertion rp id = %q", ass.RPID)
	}
	if len(ass.AllowCredentials) != 0 {
		t.Fatal("an empty allow-list should stay empty for a usernameless login")
	}
}

/* ------------------------------------------------------------- attacks --- */

// A response replayed against a different challenge must fail.
func TestWrongChallengeIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	used := challenge(t)
	authData := a.authData(cfg.RPID, flagUserPresent, false)
	clientData := a.clientDataJSON(t, "webauthn.get", b64(used.Value), cfg.Origin)

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	// Verify against a different challenge than the one that was signed.
	if _, err := cfg.FinishAssertion(challenge(t), resp, cred.PublicKey, 0); !errors.Is(err, ErrChallenge) {
		t.Fatalf("err = %v, want ErrChallenge", err)
	}
}

// This is what makes a passkey phishing-resistant: a response produced for
// another site must not verify here.
func TestWrongOriginIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	ch := challenge(t)
	authData := a.authData(cfg.RPID, flagUserPresent, false)
	clientData := a.clientDataJSON(t, "webauthn.get", b64(ch.Value), "https://evil.example.com")

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	if _, err := cfg.FinishAssertion(ch, resp, cred.PublicKey, 0); !errors.Is(err, ErrOrigin) {
		t.Fatalf("err = %v, want ErrOrigin", err)
	}
}

// A credential registered for another hostname must not work here either.
func TestWrongRPIDIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	ch := challenge(t)
	authData := a.authData("other.example.com", flagUserPresent, false)
	clientData := a.clientDataJSON(t, "webauthn.get", b64(ch.Value), cfg.Origin)

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	if _, err := cfg.FinishAssertion(ch, resp, cred.PublicKey, 0); !errors.Is(err, ErrRPID) {
		t.Fatalf("err = %v, want ErrRPID", err)
	}
}

// A signature from a different key must not verify.
func TestForgedSignatureIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	attacker := newAuthenticator(t)
	attacker.credID = a.credID

	ch := challenge(t)
	authData := attacker.authData(cfg.RPID, flagUserPresent, false)
	clientData := attacker.clientDataJSON(t, "webauthn.get", b64(ch.Value), cfg.Origin)

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(attacker.sign(t, authData, clientData))

	// Verified against the real key, so the attacker's signature must fail.
	if _, err := cfg.FinishAssertion(ch, resp, cred.PublicKey, 0); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// A counter that does not advance suggests the authenticator was cloned.
func TestCounterGoingBackwardsIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	a.count = 5
	if _, err := assert(t, a, challenge(t), cred, 10); !errors.Is(err, ErrCloned) {
		t.Fatalf("err = %v, want ErrCloned", err)
	}

	// Equal is also a failure to advance.
	a.count = 10
	if _, err := assert(t, a, challenge(t), cred, 10); !errors.Is(err, ErrCloned) {
		t.Fatalf("err = %v, want ErrCloned for an unchanged counter", err)
	}
}

// Authenticators that keep no counter report zero forever, which is allowed.
func TestZeroCounterIsAccepted(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	a.count = 0
	if _, err := assert(t, a, challenge(t), cred, 0); err != nil {
		t.Fatalf("an authenticator with no counter was rejected: %v", err)
	}
}

// Without the user-present bit, nothing happened that a person consented to.
func TestMissingUserPresenceIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	ch := challenge(t)
	authData := a.authData(cfg.RPID, 0, false) // no flags at all
	clientData := a.clientDataJSON(t, "webauthn.get", b64(ch.Value), cfg.Origin)

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	if _, err := cfg.FinishAssertion(ch, resp, cred.PublicKey, 0); !errors.Is(err, ErrNotPresent) {
		t.Fatalf("err = %v, want ErrNotPresent", err)
	}
}

// A registration response must not be replayable as an assertion.
func TestTypeConfusionIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	ch := challenge(t)
	authData := a.authData(cfg.RPID, flagUserPresent, false)
	clientData := a.clientDataJSON(t, "webauthn.create", b64(ch.Value), cfg.Origin) // wrong type

	var resp AssertionResponse
	resp.Response.ClientDataJSON = b64(clientData)
	resp.Response.AuthenticatorData = b64(authData)
	resp.Response.Signature = b64(a.sign(t, authData, clientData))

	if _, err := cfg.FinishAssertion(ch, resp, cred.PublicKey, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	a := newAuthenticator(t)
	cred, _ := register(t, a, challenge(t))

	stale, _ := NewChallenge(1, -time.Second)
	if _, err := assert(t, a, stale, cred, 0); !errors.Is(err, ErrChallenge) {
		t.Fatalf("err = %v, want ErrChallenge for an expired challenge", err)
	}
	if _, err := register(t, a, stale); !errors.Is(err, ErrChallenge) {
		t.Fatalf("err = %v, want ErrChallenge on registration", err)
	}
}

func TestChallengesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		ch, err := NewChallenge(1, time.Minute)
		if err != nil {
			t.Fatalf("new challenge: %v", err)
		}
		if len(ch.Value) != 32 {
			t.Fatalf("challenge is %d bytes, want 32", len(ch.Value))
		}
		if seen[string(ch.Value)] {
			t.Fatalf("duplicate challenge after %d draws", i)
		}
		seen[string(ch.Value)] = true
	}
}

/* ------------------------------------------------------------ parsing --- */

// Everything here runs on unauthenticated input, so it must never panic.
func TestMalformedInputIsRejected(t *testing.T) {
	ch := challenge(t)

	cases := []RegistrationResponse{
		{},
		{Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		}{ClientDataJSON: "!!!not base64!!!"}},
		{Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		}{ClientDataJSON: b64([]byte("not json")), AttestationObject: b64([]byte{0xFF})}},
	}

	for i, c := range cases {
		if _, err := cfg.FinishRegistration(ch, c); err == nil {
			t.Errorf("case %d: malformed registration accepted", i)
		}
	}
}

func FuzzParseAuthData(f *testing.F) {
	a := &fakeAuthenticator{credID: make([]byte, 32)}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.key = key

	f.Add(a.authData("gw.example.com", flagUserPresent, false))
	f.Add(a.authData("gw.example.com", flagUserPresent|flagAttestedData, true))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := parseAuthData(data)
		if err != nil {
			return
		}
		if len(parsed.RPIDHash) != 32 {
			t.Fatalf("accepted an rp id hash of %d bytes", len(parsed.RPIDHash))
		}
		if len(parsed.CredentialID) > 1023 {
			t.Fatalf("accepted a credential id of %d bytes", len(parsed.CredentialID))
		}
	})
}

func FuzzDecodeCBOR(f *testing.F) {
	f.Add([]byte{0xA0})
	f.Add([]byte{0xA1, 0x01, 0x02})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic, hang, or allocate without bound.
		_, _ = decodeCBORMap(data)
		_, _ = parseCOSEKey(data)
	})
}

// The COSE key our fake authenticator produces must decode to the real key.
func TestCOSEKeyRoundTrip(t *testing.T) {
	a := newAuthenticator(t)

	key, err := parseCOSEKey(a.coseKey())
	if err != nil {
		t.Fatalf("parse cose key: %v", err)
	}
	if key.ecdsa == nil {
		t.Fatal("expected an ecdsa key")
	}
	if key.ecdsa.X.Cmp(a.key.PublicKey.X) != 0 || key.ecdsa.Y.Cmp(a.key.PublicKey.Y) != 0 {
		t.Fatal("the decoded key does not match the original")
	}
}

func TestUnsupportedAlgorithmIsRejected(t *testing.T) {
	// map(2) { 1: 1, 3: -8 } — OKP with EdDSA, which we do not verify.
	if _, err := parseCOSEKey([]byte{0xA2, 0x01, 0x01, 0x03, 0x27}); err == nil {
		t.Fatal("an unsupported key type was accepted")
	}
}

var _ = big.NewInt // keep the import when the RSA path is not exercised here

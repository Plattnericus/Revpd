package rdp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/proxy/x224"
)

/* --------------------------------------------------------------- setup --- */

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revpd-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// recordingAuth captures what the server extracted and answers as told.
type recordingAuth struct {
	mu    sync.Mutex
	creds *Credentials
	srcIP net.IP
	calls int

	redir *Redirection
	err   error
	delay time.Duration
}

func (a *recordingAuth) Authenticate(ctx context.Context, srcIP net.IP, creds *Credentials) (*Redirection, error) {
	a.mu.Lock()
	a.calls++
	// Copy: the server clears the password once Run returns.
	cp := *creds
	a.creds = &cp
	a.srcIP = srcIP
	a.mu.Unlock()

	if a.delay > 0 {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if a.err != nil {
		return nil, a.err
	}
	return a.redir, nil
}

func (a *recordingAuth) seen() (*Credentials, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.creds, a.calls
}

// serveOnce accepts a single connection and runs the login on it.
func serveOnce(t *testing.T, auth Authenticator) (addr string, done <-chan Outcome) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	login := NewLogin(Options{
		TLSConfig:        testTLSConfig(t),
		HandshakeTimeout: 20 * time.Second,
		StepTimeout:      10 * time.Second,
	}, auth)

	// The goroutine below borrows t, so it must not outlive the test. Tests
	// that ignore the outcome would otherwise leave it logging into a finished
	// test, which panics.
	finished := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-finished
	})

	out := make(chan Outcome, 1)
	go func() {
		defer close(finished)

		conn, err := ln.Accept()
		if err != nil {
			out <- OutcomeFailed
			return
		}
		defer conn.Close()

		// The caller normally reads the connection request first, so mirror that.
		cr, err := x224.Read(newReader(conn))
		if err != nil {
			out <- OutcomeFailed
			return
		}

		outcome, _, err := login.run(context.Background(), conn, cr, net.ParseIP("203.0.113.7"))
		if err != nil {
			t.Logf("login ended: %v", err)
		}
		out <- outcome
	}()

	return ln.Addr().String(), out
}

/* ------------------------------------------------------ the whole thing --- */

// The full sequence, end to end: X.224, TLS, MCS, credentials, redirection.
func TestLoginSequenceEndToEnd(t *testing.T) {
	auth := &recordingAuth{redir: &Redirection{
		SessionID: 42,
		Token:     "abc123token",
		Username:  "felix",
		Domain:    "CORP",
		Password:  "TheRealWindowsPassword",
	}}

	addr, done := serveOnce(t, auth)

	c, err := dialTestClient(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	selected, err := c.handshake("felix", ProtocolRDP|ProtocolSSL)
	if err != nil {
		t.Fatalf("x224 handshake: %v", err)
	}
	if selected != ProtocolSSL {
		t.Fatalf("server selected protocol %d, want SSL(%d)", selected, ProtocolSSL)
	}

	if err := c.startTLS(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	if err := c.mcsConnect([]string{"rdpdr", "cliprdr", "rdpsnd"}, ProtocolSSL); err != nil {
		t.Fatalf("mcs connect: %v", err)
	}

	if err := c.sendClientInfo("CORP", "felix", "MyPassword,123456"); err != nil {
		t.Fatalf("send client info: %v", err)
	}

	// The licence answer comes first, then the redirection.
	if err := c.expectLicense(); err != nil {
		t.Fatalf("licence: %v", err)
	}

	got, err := c.readRedirection()
	if err != nil {
		t.Fatalf("read redirection: %v", err)
	}

	if outcome := <-done; outcome != OutcomeRedirected {
		t.Fatalf("outcome = %s, want redirected", outcome)
	}

	// The server must have seen exactly what the client typed.
	creds, calls := auth.seen()
	if calls != 1 {
		t.Fatalf("authenticator called %d times, want 1", calls)
	}
	if creds.Username != "felix" || creds.Domain != "CORP" {
		t.Fatalf("credentials = %q\\%q, want CORP\\felix", creds.Domain, creds.Username)
	}
	if creds.Password != "MyPassword,123456" {
		t.Fatalf("password = %q, want the raw field including the suffix", creds.Password)
	}

	// And the client must have received a usable redirection.
	if got.token != "Cookie: msts=abc123token\r\n" {
		t.Fatalf("routing token = %q", got.token)
	}
	if got.username != "felix" || got.password != "TheRealWindowsPassword" {
		t.Fatalf("redirection carried %q / %q", got.username, got.password)
	}
	if got.sessionID != 42 {
		t.Fatalf("session id = %d, want 42", got.sessionID)
	}
	if got.flags&lbTargetNetAddress != 0 {
		t.Fatal("LB_TARGET_NET_ADDRESS was set; the client would not come back to us")
	}
}

// The token the client will send back must be exactly what our own X.224
// parser reads. This is the seam between the two halves of the design.
func TestRoutingTokenRoundTripsThroughX224Parser(t *testing.T) {
	token := "s7Kd92LmQx0Pw"

	// What the server puts in the redirection...
	emitted := routingToken(token)

	// ...becomes the routing token of the client's next connection request.
	variable := append([]byte{}, emitted...)
	variable = append(variable, negTypeRequest, 0x00, 0x08, 0x00)
	variable = append(variable, le32(ProtocolSSL)...)

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	body = append(body, variable...)

	pkt := []byte{3, 0, 0, byte(4 + len(body))}
	pkt = append(pkt, body...)

	cr, err := x224.Read(newReaderFromBytes(pkt))
	if err != nil {
		t.Fatalf("x224 parse: %v", err)
	}
	if cr.RoutingToken != token {
		t.Fatalf("routing token round trip gave %q, want %q", cr.RoutingToken, token)
	}
	if cr.Cookie != "" {
		t.Fatalf("routing token leaked into the cookie field: %q", cr.Cookie)
	}
}

// A rejected login must not redirect, and must not say why.
func TestFailedAuthSendsNoRedirection(t *testing.T) {
	auth := &recordingAuth{err: errors.New("wrong password")}
	addr, done := serveOnce(t, auth)

	c, err := dialTestClient(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	if _, err := c.handshake("felix", ProtocolSSL); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := c.startTLS(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	if err := c.mcsConnect([]string{"rdpdr"}, ProtocolSSL); err != nil {
		t.Fatalf("mcs: %v", err)
	}
	if err := c.sendClientInfo("", "felix", "wrong,000000"); err != nil {
		t.Fatalf("client info: %v", err)
	}
	if err := c.expectLicense(); err != nil {
		t.Fatalf("licence: %v", err)
	}

	if _, err := c.readRedirection(); err == nil {
		t.Fatal("a redirection was sent despite authentication failing")
	}
	if outcome := <-done; outcome != OutcomeRejected {
		t.Fatalf("outcome = %s, want rejected", outcome)
	}
}

// A client that will not do TLS must be told, not silently dropped.
func TestClientWithoutTLSIsRefused(t *testing.T) {
	addr, done := serveOnce(t, &recordingAuth{})

	c, err := dialTestClient(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	_, err = c.handshake("felix", ProtocolRDP)
	if err == nil {
		t.Fatal("server accepted a client offering only legacy RDP security")
	}
	if !strings.Contains(err.Error(), "negotiation failed") {
		t.Fatalf("expected a negotiation failure, got %v", err)
	}
	if outcome := <-done; outcome != OutcomeRejected {
		t.Fatalf("outcome = %s, want rejected", outcome)
	}
}

// Channels the client asks for must all come back with ids.
func TestChannelsAreAssigned(t *testing.T) {
	auth := &recordingAuth{redir: &Redirection{Token: "t"}}
	addr, _ := serveOnce(t, auth)

	c, err := dialTestClient(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	c.handshake("felix", ProtocolSSL)
	if err := c.startTLS(); err != nil {
		t.Fatalf("tls: %v", err)
	}

	names := []string{"rdpdr", "cliprdr", "rdpsnd", "drdynvc"}
	if err := c.mcsConnect(names, ProtocolSSL); err != nil {
		t.Fatalf("mcs: %v", err)
	}

	// The I/O channel plus one per requested channel.
	if len(c.channels) != len(names)+1 {
		t.Fatalf("server assigned %d channels, want %d", len(c.channels), len(names)+1)
	}
	if c.channels[0] != mcsIOChannel {
		t.Fatalf("first channel is %d, want the I/O channel %d", c.channels[0], mcsIOChannel)
	}

	seen := map[uint16]bool{}
	for _, ch := range c.channels {
		if seen[ch] {
			t.Fatalf("channel id %d handed out twice", ch)
		}
		seen[ch] = true
	}
}

/* ------------------------------------------------------- password split --- */

// Windows passwords may contain commas, so only the last one separates.
func TestSplitPassword(t *testing.T) {
	cases := []struct {
		raw      string
		password string
		factor   string
	}{
		{"MyPassword,123456", "MyPassword", "123456"},
		{"MyPassword,push", "MyPassword", "push"},
		{"MyPassword,K7RM2-9XQPD", "MyPassword", "K7RM2-9XQPD"},

		// A comma inside the password must survive: only the last one splits.
		{"Hello,World,123456", "Hello,World", "123456"},
		{"a,b,c,d,999999", "a,b,c,d", "999999"},

		// Whitespace around the factor is a typing artefact, not part of it.
		{"pw, 123456 ", "pw", "123456"},

		// No comma at all: everything is the password and there is no factor.
		{"JustAPassword", "JustAPassword", ""},

		// Degenerate shapes must not panic or silently pass.
		{"", "", ""},
		{",", "", ""},
		{"pw,", "pw", ""},
		{",123456", "", "123456"},
	}

	for _, tc := range cases {
		pw, factor := SplitPassword(tc.raw)
		if pw != tc.password || factor != tc.factor {
			t.Errorf("SplitPassword(%q) = %q, %q; want %q, %q", tc.raw, pw, factor, tc.password, tc.factor)
		}
	}
}

/* --------------------------------------------------------------- units --- */

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"felix", "CORP", "Müller", "日本語", "a", "", "emoji 😀 here"} {
		if got := decodeUTF16(utf16le(s)); got != s {
			t.Errorf("utf16 round trip of %q gave %q", s, got)
		}
	}
}

// A null terminator ends the string; padding after it must not leak in.
func TestDecodeUTF16StopsAtNull(t *testing.T) {
	b := append(utf16le("felix"), 0x00, 0x00)
	b = append(b, utf16le("junk")...)

	if got := decodeUTF16(b); got != "felix" {
		t.Fatalf("decodeUTF16 = %q, want felix", got)
	}
}

func TestClientInfoRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00},
		append(le16(secInfoPkt), le16(0)...),        // header only
		append(le16(secLicensePkt), le16(0)...),     // wrong pdu type
		append(le16(secInfoPkt|secEncrypt), make([]byte, 40)...), // encrypted
	}

	for i, in := range cases {
		if _, err := parseClientInfo(in); err == nil {
			t.Errorf("case %d: malformed client info was accepted", i)
		}
	}
}

// The parser faces unauthenticated input, so it must never panic.
func FuzzParseClientInfo(f *testing.F) {
	good := make([]byte, 0, 64)
	good = append(good, le16(secInfoPkt)...)
	good = append(good, le16(0)...)
	good = append(good, le32(0)...)
	good = append(good, le32(infoUnicode)...)
	good = append(good, le16(0)...)
	good = append(good, le16(10)...)
	good = append(good, le16(8)...)
	good = append(good, le16(0)...)
	good = append(good, le16(0)...)
	good = append(good, 0, 0)
	good = append(good, append(utf16le("felix"), 0, 0)...)
	good = append(good, append(utf16le("pw,1"), 0, 0)...)

	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0x40, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		creds, err := parseClientInfo(data)
		if err != nil {
			return
		}
		if creds.Username == "" {
			t.Fatal("accepted a client info pdu with no username")
		}
		// Splitting must never panic regardless of what came in.
		SplitPassword(creds.Password)
	})
}

func FuzzParseConnectInitial(f *testing.F) {
	f.Add(buildTestConnectInitial([]string{"rdpdr"}, ProtocolSSL))
	f.Add([]byte{0x7F, 0x65, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		blocks, err := parseConnectInitial(data)
		if err != nil {
			return
		}
		if len(blocks.channels) > 31 {
			t.Fatalf("accepted %d virtual channels", len(blocks.channels))
		}
	})
}

// The redirection packet's own length field has to match what we emitted.
func TestRedirectionPacketLengthIsConsistent(t *testing.T) {
	pkt := buildRedirectionPacket(Redirection{
		SessionID: 7, Token: "tok", Username: "u", Domain: "d", Password: "p",
	})

	declared := int(uint16(pkt[2]) | uint16(pkt[3])<<8)
	if declared != len(pkt) {
		t.Fatalf("packet declares %d bytes but is %d", declared, len(pkt))
	}
}

// Without credentials the packet must not claim to carry them.
func TestRedirectionWithoutCredentials(t *testing.T) {
	got, err := parseRedirectionPacket(buildRedirectionPacket(Redirection{Token: "tok"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.flags&lbPassword != 0 {
		t.Fatal("password flag set with no password")
	}
	if got.flags&lbUsername != 0 {
		t.Fatal("username flag set with no username")
	}
	if got.flags&lbLoadBalanceInfo == 0 {
		t.Fatal("load balance info flag missing")
	}
}

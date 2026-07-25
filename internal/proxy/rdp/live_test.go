package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

/*
   The RDP-native login against a gateway that is actually running, which is
   the one thing the in-process tests cannot tell you: that a real deployment
   negotiates TLS without NLA, reads the credentials out of the Client Info
   PDU and answers with a redirection the client can act on.

   Skipped unless it is pointed at a gateway:

     REVPD_LIVE_GATEWAY=192.168.178.210:3389 \
     REVPD_LIVE_USER=felix \
     REVPD_LIVE_PASSWORD='...' \
     REVPD_LIVE_TOTP_SECRET=... \
     REVPD_LIVE_TARGET_CN=Nexors-PC \
     go test ./internal/proxy/rdp -run TestLive -v

   It must run from an address that holds no grant, or the relay forwards the
   connection instead of asking for credentials.
*/

type liveEnv struct {
	gateway  string
	user     string
	password string
	secret   string
	targetCN string
}

func liveSetup(t *testing.T) liveEnv {
	t.Helper()

	e := liveEnv{
		gateway:  os.Getenv("REVPD_LIVE_GATEWAY"),
		user:     os.Getenv("REVPD_LIVE_USER"),
		password: os.Getenv("REVPD_LIVE_PASSWORD"),
		secret:   os.Getenv("REVPD_LIVE_TOTP_SECRET"),
		targetCN: os.Getenv("REVPD_LIVE_TARGET_CN"),
	}
	if e.gateway == "" {
		t.Skip("set REVPD_LIVE_GATEWAY to run against a live gateway")
	}
	if e.user == "" || e.password == "" || e.secret == "" {
		t.Fatal("REVPD_LIVE_USER, REVPD_LIVE_PASSWORD and REVPD_LIVE_TOTP_SECRET are all required")
	}
	return e
}

// TestLiveAWrongCodeIsRefused proves the second factor is load-bearing: the
// right password with a wrong code must not produce a redirection.
//
// Named to sort before the test that signs in, because a successful login
// leaves a grant behind and the relay would then forward this connection
// straight to the machine instead of asking for anything.
func TestLiveAWrongCodeIsRefused(t *testing.T) {
	env := liveSetup(t)

	c, err := dialTestClient(env.gateway)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()

	if _, err := c.handshake(env.user, ProtocolRDP|ProtocolSSL); err != nil {
		// The target answered instead of the login, which only happens when
		// this address already holds a grant.
		t.Skipf("relayed to the target rather than asked for credentials (%v) — "+
			"a grant for this address is still open, wait for it to expire", err)
	}
	if err := c.startTLS(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	if err := c.mcsConnect([]string{"rdpdr"}, ProtocolSSL); err != nil {
		t.Fatalf("mcs connect: %v", err)
	}
	if err := c.sendClientInfo("", env.user, env.password+",000000"); err != nil {
		t.Fatalf("send client info: %v", err)
	}

	// Either the connection is dropped or nothing usable comes back. What must
	// not happen is a redirection.
	if err := c.expectLicense(); err != nil {
		t.Logf("refused, connection ended: %v", err)
		return
	}
	if redir, err := c.readRedirection(); err == nil {
		t.Fatalf("a wrong one-time code still produced a redirection for %q", redir.username)
	}
	t.Log("refused, no redirection issued")
}

// TestLiveLoginRedirectsAndRelays walks the whole of the normal way in: type a
// password and a one-time code into the Windows client, get redirected, come
// back with the token and land on the machine.
func TestLiveLoginRedirectsAndRelays(t *testing.T) {
	env := liveSetup(t)

	code, err := totp.GenerateCode(strings.ToUpper(strings.TrimSpace(env.secret)), time.Now())
	if err != nil {
		t.Fatalf("generate a one-time code: %v", err)
	}

	c, err := dialTestClient(env.gateway)
	if err != nil {
		t.Fatalf("dial %s: %v", env.gateway, err)
	}
	defer c.close()

	// mstsc offers both; a gateway that wants to read the credentials has to
	// come back with plain TLS, because NLA would keep them from us.
	selected, err := c.handshake(env.user, ProtocolRDP|ProtocolSSL)
	if err != nil {
		t.Fatalf("x224 handshake: %v", err)
	}
	if selected != ProtocolSSL {
		t.Fatalf("gateway selected protocol %d, want SSL(%d) so the login can read the credentials",
			selected, ProtocolSSL)
	}
	t.Log("x224: gateway selected TLS without NLA")

	if err := c.startTLS(); err != nil {
		t.Fatalf("tls to the gateway: %v", err)
	}
	t.Logf("tls: %s", tlsVersionName(c.tls.ConnectionState().Version))

	if err := c.mcsConnect([]string{"rdpdr", "cliprdr", "rdpsnd", "drdynvc"}, ProtocolSSL); err != nil {
		t.Fatalf("mcs connect: %v", err)
	}

	// The Duo convention: the one-time code rides on the password field.
	if err := c.sendClientInfo("", env.user, env.password+","+code); err != nil {
		t.Fatalf("send client info: %v", err)
	}
	if err := c.expectLicense(); err != nil {
		t.Fatalf("licence: %v", err)
	}

	redir, err := c.readRedirection()
	if err != nil {
		t.Fatalf("no redirection came back: %v", err)
	}

	token := strings.TrimPrefix(strings.TrimSuffix(redir.token, "\r\n"), "Cookie: msts=")
	if token == "" {
		t.Fatal("the redirection carries no routing token")
	}
	if redir.username != env.user {
		t.Errorf("redirection names %q, want %q", redir.username, env.user)
	}
	if redir.password != env.password {
		t.Error("the redirection does not carry the password the client typed")
	}
	if strings.Contains(redir.password, code) {
		t.Error("the one-time code was passed through to Windows instead of being consumed")
	}
	t.Logf("redirection: token %d chars, user %q, session %d",
		len(token), redir.username, redir.sessionID)

	c.close()

	// What mstsc does next, byte for byte: reconnect carrying the token.
	back, err := net.DialTimeout("tcp", env.gateway, 10*time.Second)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer back.Close()

	if _, err := back.Write(routingTokenCR(token)); err != nil {
		t.Fatalf("send the routing token: %v", err)
	}

	back.SetDeadline(time.Now().Add(20 * time.Second))
	cc, err := readRawTPKT(back)
	if err != nil {
		t.Fatalf("the machine did not answer through the relay: %v", err)
	}
	if len(cc) < 6 || cc[5] != 0xD0 {
		t.Fatalf("expected a connection confirm, got % x", cc[:min(len(cc), 12)])
	}
	t.Logf("relay: the target answered with a connection confirm (%d bytes)", len(cc))

	// Stop at TLS. Going further would put credentials in front of the real
	// Windows logon, and a wrong one there counts against the account.
	if env.targetCN != "" {
		tc := tls.Client(back, &tls.Config{InsecureSkipVerify: true})
		tc.SetDeadline(time.Now().Add(20 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatalf("tls through the relay to the target: %v", err)
		}
		cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName
		if !strings.EqualFold(cn, env.targetCN) {
			t.Errorf("the tunnel ends at %q, want %q", cn, env.targetCN)
		}
		t.Logf("tunnel: %s, certificate cn=%s", tlsVersionName(tc.ConnectionState().Version), cn)
	}
}

// routingTokenCR is the reconnect mstsc sends after a redirection: the token,
// and the same negotiation request as any other connection. Leaving the
// negotiation out makes a target that requires NLA hang up without a word.
func routingTokenCR(token string) []byte {
	variable := []byte("Cookie: msts=" + token + "\r\n")

	neg := make([]byte, 8)
	neg[0] = 0x01 // RDP_NEG_REQ
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], ProtocolSSL|ProtocolHybrid)
	variable = append(variable, neg...)

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	body = append(body, variable...)

	total := 4 + len(body)
	pkt := make([]byte, 4, total)
	pkt[0] = 3
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	return append(pkt, body...)
}

func readRawTPKT(conn net.Conn) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if head[0] != 3 {
		return nil, fmt.Errorf("not a TPKT packet: 0x%02x", head[0])
	}
	length := int(binary.BigEndian.Uint16(head[2:4]))
	if length < 4 || length > 8192 {
		return nil, fmt.Errorf("implausible length %d", length)
	}
	rest := make([]byte, length-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return append(head, rest...), nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}

//go:build integration

// The production path, end to end, with nothing stubbed out.
//
// A client speaks real RDP to the real relay, which runs the real login, which
// asks the real policy engine, which checks a real Argon2id password and a
// real TOTP code, sends a real magic packet, waits for the machine, and hands
// back a Server Redirection. The client then reconnects with the routing token
// and the relay forwards it to the target.
//
// This is the one test that would catch a break anywhere along that chain.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/plattnericus/revpd/internal/audit"
	"github.com/plattnericus/revpd/internal/auth"
	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/crypto"
	"github.com/plattnericus/revpd/internal/mfa"
	"github.com/plattnericus/revpd/internal/policy"
	"github.com/plattnericus/revpd/internal/proxy/rdp"
	"github.com/plattnericus/revpd/internal/proxy/relay"
	"github.com/plattnericus/revpd/internal/store"
	"github.com/pquerna/otp/totp"
)

/* ------------------------------------------------------------- gateway --- */

type liveGateway struct {
	relay  *relay.Server
	db     *store.DB
	log    *audit.Log
	win    *fakeWindows
	wol    *wolSink
	secret string
}

const livePassword = "CorrectHorseBatteryStaple"

// startGateway wires the same components cmd/revpd wires in production.
func startGateway(t *testing.T, asleep bool) *liveGateway {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	log, err := audit.New(db.DB)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	win := newFakeWindows(t, asleep, 300*time.Millisecond)
	sink := newWolSink(t, win.wake)

	cfg := config.Defaults()
	cfg.Web.Hostname = "gw.test"
	cfg.WoL.ProbeInterval = 40 * time.Millisecond
	cfg.WoL.ProbeSettle = 0
	cfg.WoL.Repeat = 1
	cfg.Grant.TTL = time.Minute

	key, _ := crypto.NewMasterKey()
	sealer, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	hash, err := crypto.HashPassword(livePassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	uid, err := db.CreateUser(ctx, store.User{
		Username: "felix", DisplayName: "Felix", PasswordHash: hash, Role: "user", RDPHint: "felix",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret, _, err := mfa.TOTP{Skew: cfg.Auth.TOTPSkew}.Enroll("revpd", "felix")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	enc, _ := sealer.Seal(fmt.Sprintf("totp:%d", uid), []byte(secret))
	if err := db.SetTOTPSecret(ctx, uid, enc); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	tid, err := db.CreateTarget(ctx, store.Target{
		Name: "Büro-PC", IP: "127.0.0.1", RDPPort: win.port(),
		MAC: "a8:a1:59:3c:d2:11", WoLBroadcast: "127.0.0.1", WoLPort: sink.port(),
		BootTimeoutS: 5,
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := db.GrantTargetAccess(ctx, uid, tid); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	am := auth.NewManager(db, auth.Options{
		TTL: time.Hour, Idle: time.Hour, MaxFailures: 50,
		LockoutBase: time.Millisecond, LockoutMax: time.Second,
	})
	engine := policy.New(db, log, cfg, nil).WithSecrets(sealer, am)

	login := rdp.NewLogin(rdp.Options{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12},
		HandshakeTimeout: 30 * time.Second,
		StepTimeout:      10 * time.Second,
	}, engine)

	srv := relay.New(relay.Options{
		Listen:      "127.0.0.1:0",
		PeekTimeout: 5 * time.Second,
		DialTimeout: 5 * time.Second,
		IdleTimeout: time.Minute,
		Login:       login,
	}, engine, engine)

	rctx, cancel := context.WithCancel(ctx)
	go srv.Serve(rctx)
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("relay never bound")
	}
	t.Cleanup(cancel)

	return &liveGateway{relay: srv, db: db, log: log, win: win, wol: sink, secret: secret}
}

func (g *liveGateway) addr() string { return g.relay.Addr().String() }

func (g *liveGateway) code(t *testing.T) string {
	t.Helper()
	c, err := totp.GenerateCode(g.secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return c
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gw.test"},
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

/* -------------------------------------------------------- an rdp client --- */

// rdpClient speaks the client half of the sequence, the way mstsc does.
type rdpClient struct {
	conn net.Conn
	tls  *tls.Conn
	r    *bufio.Reader

	userID   uint16
	channels []uint16
}

func dialRDP(t *testing.T, addr string) *rdpClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	t.Cleanup(func() { conn.Close() })

	return &rdpClient{conn: conn, r: bufio.NewReader(conn)}
}

func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func tpkt(payload []byte) []byte {
	out := make([]byte, 4, 4+len(payload))
	out[0] = 3
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(payload)))
	return append(out, payload...)
}

func (c *rdpClient) readTPKT() ([]byte, error) {
	var head [4]byte
	if _, err := readFull(c.r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 3 {
		return nil, fmt.Errorf("tpkt version 0x%02x", head[0])
	}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if n < 4 || n > 16*1024 {
		return nil, fmt.Errorf("tpkt length %d", n)
	}
	body := make([]byte, n-4)
	_, err := readFull(c.r, body)
	return body, err
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// connectionRequest is the first packet, offering TLS.
func connectionRequestFor(cookie, routingToken string) []byte {
	var variable []byte
	switch {
	case routingToken != "":
		variable = []byte("Cookie: msts=" + routingToken + "\r\n")
	case cookie != "":
		variable = []byte("Cookie: mstshash=" + cookie + "\r\n")
	}
	variable = append(variable, 0x01, 0x00, 0x08, 0x00)
	variable = append(variable, le32(0x00000001)...) // PROTOCOL_SSL

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	return tpkt(append(body, variable...))
}

// negotiate performs X.224 and starts TLS.
func (c *rdpClient) negotiate(t *testing.T, cookie, routingToken string) {
	t.Helper()

	if _, err := c.conn.Write(connectionRequestFor(cookie, routingToken)); err != nil {
		t.Fatalf("write connection request: %v", err)
	}

	body, err := c.readTPKT()
	if err != nil {
		t.Fatalf("read connection confirm: %v", err)
	}
	if len(body) < 15 || body[1] != 0xD0 {
		t.Fatalf("not a connection confirm: % x", body)
	}
	if body[7] == 0x03 {
		t.Fatalf("server refused the negotiation, code %d", binary.LittleEndian.Uint32(body[11:15]))
	}
	if got := binary.LittleEndian.Uint32(body[11:15]); got != 0x00000001 {
		t.Fatalf("server selected protocol %d, want SSL", got)
	}

	c.tls = tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
	if err := c.tls.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	c.r = bufio.NewReader(c.tls)
}

func (c *rdpClient) writeData(payload []byte) error {
	out := append([]byte{0x02, 0xF0, 0x80}, payload...)
	_, err := c.tls.Write(tpkt(out))
	return err
}

func (c *rdpClient) readData(t *testing.T) []byte {
	t.Helper()

	body, err := c.readTPKT()
	if err != nil {
		t.Fatalf("read data tpdu: %v", err)
	}
	if len(body) < 3 {
		t.Fatalf("data tpdu is %d bytes", len(body))
	}
	return body[3:]
}

/* ------------------------------------------------------- mcs encoding --- */

// berLength and berTagged cover the shapes T.125 uses for Connect Initial.
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func berTagged(tag byte, body []byte) []byte {
	out := append([]byte{tag}, berLength(len(body))...)
	return append(out, body...)
}

func berInteger(v uint32) []byte {
	switch {
	case v < 0x80:
		return berTagged(0x02, []byte{byte(v)})
	case v < 0x8000:
		return berTagged(0x02, []byte{byte(v >> 8), byte(v)})
	default:
		return berTagged(0x02, []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
}

func domainParameters() []byte {
	var b []byte
	for _, v := range []uint32{34, 3, 0, 1, 0, 1, 65535, 2} {
		b = append(b, berInteger(v)...)
	}
	return berTagged(0x30, b)
}

// userDataBlock prefixes a body with its type and total length.
func userDataBlock(t uint16, body []byte) []byte {
	out := append(le16(t), le16(uint16(len(body)+4))...)
	return append(out, body...)
}

// buildConnectInitial assembles the packet mstsc opens the MCS phase with.
func buildConnectInitial() []byte {
	// CS_CORE: 128 fixed bytes, then the requested protocol.
	core := make([]byte, 128)
	binary.LittleEndian.PutUint32(core[0:4], 0x00080004)
	binary.LittleEndian.PutUint16(core[4:6], 1920)
	binary.LittleEndian.PutUint16(core[6:8], 1080)
	core = append(core, le32(0x00000001)...) // PROTOCOL_SSL

	// CS_NET with two virtual channels, as a real client asks for.
	netData := le32(2)
	for _, name := range []string{"rdpdr", "cliprdr"} {
		n := make([]byte, 8)
		copy(n, name)
		netData = append(netData, n...)
		netData = append(netData, le32(0)...)
	}

	userData := append(userDataBlock(0xC001, core), userDataBlock(0xC003, netData)...)

	// GCC Conference Create Request, PER encoded.
	gcc := []byte{0x00}                                     // choice
	gcc = append(gcc, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01)   // t124 object identifier
	gcc = append(gcc, perLength(len(userData)+14)...)       // length
	gcc = append(gcc, 0xC1, 0x08, 0x00, 0x10, 0x00, 0x01)   // choice, selection, "1", padding, sets
	gcc = append(gcc, 0xC0, 0x00)                           // choice, octet string length 0
	gcc = append(gcc, []byte("Duca")...)                    // client-to-server key
	gcc = append(gcc, perLength(len(userData))...)
	gcc = append(gcc, userData...)

	inner := berTagged(0x04, []byte{0x01})            // callingDomainSelector
	inner = append(inner, berTagged(0x04, []byte{0x01})...) // calledDomainSelector
	inner = append(inner, berTagged(0x01, []byte{0xFF})...) // upwardFlag
	inner = append(inner, domainParameters()...)            // target
	inner = append(inner, domainParameters()...)            // minimum
	inner = append(inner, domainParameters()...)            // maximum
	inner = append(inner, berTagged(0x04, gcc)...)          // userData

	out := append([]byte{0x7F, 0x65}, berLength(len(inner))...)
	return append(out, inner...)
}

// channelsFromResponse pulls the assigned channel ids out of Connect Response.
func channelsFromResponse(t *testing.T, body []byte) []uint16 {
	t.Helper()

	idx := bytes.Index(body, []byte("McDn"))
	if idx < 0 {
		t.Fatalf("connect response has no McDn key: % x", firstBytes(body))
	}

	// A PER length, then the server data blocks.
	p := idx + 4
	n := int(body[p])
	p++
	if n&0x80 != 0 {
		n = (n&0x7F)<<8 | int(body[p])
		p++
	}
	if p+n > len(body) {
		t.Fatalf("server user data claims %d bytes, %d left", n, len(body)-p)
	}
	blocks := body[p : p+n]

	for len(blocks) >= 4 {
		typ := binary.LittleEndian.Uint16(blocks[0:2])
		length := int(binary.LittleEndian.Uint16(blocks[2:4]))
		if length < 4 || length > len(blocks) {
			t.Fatalf("server block 0x%04x has length %d", typ, length)
		}

		if typ == 0x0C03 { // SC_NET
			b := blocks[4:length]
			io := binary.LittleEndian.Uint16(b[0:2])
			count := int(binary.LittleEndian.Uint16(b[2:4]))

			out := []uint16{io}
			for i := 0; i < count; i++ {
				off := 4 + i*2
				out = append(out, binary.LittleEndian.Uint16(b[off:off+2]))
			}
			return out
		}
		blocks = blocks[length:]
	}
	t.Fatal("connect response has no SC_NET block")
	return nil
}

/* ------------------------------------------------------------- the mcs --- */

// mcsConnect runs Connect Initial through the channel joins.
func (c *rdpClient) mcsConnect(t *testing.T) {
	t.Helper()

	if err := c.writeData(buildConnectInitial()); err != nil {
		t.Fatalf("write connect initial: %v", err)
	}

	resp := c.readData(t)
	c.channels = channelsFromResponse(t, resp)

	// Erect Domain, then Attach User.
	c.writeData([]byte{0x04, 0x01, 0x00, 0x01, 0x00})
	c.writeData([]byte{0x28})

	confirm := c.readData(t)
	if len(confirm) < 4 || confirm[0]&^0x03 != 0x2C {
		t.Fatalf("expected attach user confirm, got % x", confirm)
	}
	c.userID = binary.BigEndian.Uint16(confirm[2:4]) + 1001

	for _, ch := range c.channels {
		req := []byte{0x38}
		req = append(req, byte((c.userID-1001)>>8), byte(c.userID-1001))
		req = append(req, byte(ch>>8), byte(ch))

		c.writeData(req)
		if got := c.readData(t); got[0]&^0x03 != 0x3C {
			t.Fatalf("expected channel join confirm for %d, got % x", ch, got)
		}
	}
}

// sendClientInfo delivers the credentials, which is where the MFA suffix rides.
func (c *rdpClient) sendClientInfo(t *testing.T, domain, username, password string) {
	t.Helper()

	d, u, p := utf16le(domain), utf16le(username), utf16le(password)

	info := append([]byte{}, le16(0x0040)...) // SEC_INFO_PKT
	info = append(info, le16(0)...)
	info = append(info, le32(0)...)
	info = append(info, le32(0x00000010)...) // INFO_UNICODE
	info = append(info, le16(uint16(len(d)))...)
	info = append(info, le16(uint16(len(u)))...)
	info = append(info, le16(uint16(len(p)))...)
	info = append(info, le16(0)...) // cbAlternateShell
	info = append(info, le16(0)...) // cbWorkingDir
	info = append(info, append(d, 0, 0)...)
	info = append(info, append(u, 0, 0)...)
	info = append(info, append(p, 0, 0)...)
	info = append(info, 0, 0, 0, 0)

	// MCS Send Data Request on the I/O channel.
	out := []byte{0x64}
	out = append(out, byte((c.userID-1001)>>8), byte(c.userID-1001))
	out = append(out, 0x03, 0xEB) // channel 1003
	out = append(out, 0x70)
	out = append(out, perLength(len(info))...)
	out = append(out, info...)

	if err := c.writeData(out); err != nil {
		t.Fatalf("send client info: %v", err)
	}
}

func perLength(n int) []byte {
	if n > 0x7F {
		return []byte{byte(uint16(n)>>8 | 0x80), byte(n)}
	}
	return []byte{byte(n)}
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// readRedirection consumes the licence PDU then decodes the redirection.
func (c *rdpClient) readRedirection(t *testing.T) (token, username, password string) {
	t.Helper()

	// Licence first; the client knows this from where it is in the sequence.
	lic := c.ioPayload(t)
	if len(lic) < 4 || binary.LittleEndian.Uint16(lic[0:2])&0x0080 == 0 {
		t.Fatalf("expected a licence pdu, got % x", firstBytes(lic))
	}

	pdu := c.ioPayload(t)
	if len(pdu) < 9 {
		t.Fatalf("redirection pdu is %d bytes", len(pdu))
	}
	if binary.LittleEndian.Uint16(pdu[2:4])&0x000F != 0x000A {
		t.Fatalf("not a server redirection: pduType 0x%04x", binary.LittleEndian.Uint16(pdu[2:4]))
	}

	b := pdu[8:] // past share control header and pad2Octets
	flags := binary.LittleEndian.Uint32(b[8:12])
	rest := b[12:]

	field := func() []byte {
		n := int(binary.LittleEndian.Uint32(rest[0:4]))
		rest = rest[4:]
		if n > len(rest) {
			t.Fatalf("redirection field of %d bytes does not fit in %d", n, len(rest))
		}
		out := rest[:n]
		rest = rest[n:]
		return out
	}

	if flags&0x00000002 != 0 { // LB_LOAD_BALANCE_INFO
		raw := string(field())
		token = raw
	}
	if flags&0x00000004 != 0 { // LB_USERNAME
		username = decodeUTF16LE(field())
	}
	if flags&0x00000008 != 0 { // LB_DOMAIN
		decodeUTF16LE(field())
	}
	if flags&0x00000010 != 0 { // LB_PASSWORD
		password = decodeUTF16LE(field())
	}
	return token, username, password
}

// ioPayload reads the next MCS Send Data Indication on the I/O channel.
func (c *rdpClient) ioPayload(t *testing.T) []byte {
	t.Helper()

	for i := 0; i < 16; i++ {
		body := c.readData(t)
		if len(body) == 0 || body[0]&^0x03 != 0x68 {
			continue
		}

		cur := 1
		cur += 2 // initiator
		cur += 2 // channel
		cur++    // priority

		n := int(body[cur])
		cur++
		if n&0x80 != 0 {
			n = (n&0x7F)<<8 | int(body[cur])
			cur++
		}
		if cur+n > len(body) {
			t.Fatalf("send data indication claims %d bytes, %d left", n, len(body)-cur)
		}
		return body[cur : cur+n]
	}
	t.Fatal("no io payload arrived")
	return nil
}

func decodeUTF16LE(b []byte) string {
	out := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i : i+2])
		if u == 0 {
			break
		}
		out = append(out, rune(u))
	}
	return string(out)
}

func firstBytes(b []byte) []byte {
	if len(b) > 16 {
		return b[:16]
	}
	return b
}

/* ------------------------------------------------------------ the test --- */

// Everything, in one go: a sleeping machine, a password with the code
// appended, Wake-on-LAN, a redirection, a reconnect, and forwarded bytes.
func TestRDPLoginToForwardedSessionEndToEnd(t *testing.T) {
	g := startGateway(t, true) // target starts powered off
	ctx := context.Background()

	if aliveAt(g.win) {
		t.Fatal("target answered before it was woken")
	}

	// ── 1. Log in through RDP, exactly as mstsc would ───────────────────
	c := dialRDP(t, g.addr())
	c.negotiate(t, "felix", "")
	c.mcsConnect(t)
	c.sendClientInfo(t, "", "felix", livePassword+","+g.code(t))

	token, gotUser, gotPassword := c.readRedirection(t)

	if token == "" {
		t.Fatal("no routing token in the redirection")
	}
	if gotUser != "felix" {
		t.Fatalf("redirection username = %q", gotUser)
	}
	if gotPassword != livePassword {
		t.Fatalf("redirection password = %q, want the password without the code", gotPassword)
	}

	// ── 2. The magic packet really went out ─────────────────────────────
	if len(g.wol.packets()) == 0 {
		t.Fatal("no magic packet was sent")
	}

	// ── 3. The client reconnects carrying the token, as mstsc does ──────
	//
	// The token arrives wrapped as "Cookie: msts=<value>\r\n"; strip the
	// wrapper the way a client does before putting it in the next request.
	inner := token
	if after, ok := bytes.CutPrefix([]byte(token), []byte("Cookie: msts=")); ok {
		inner = string(bytes.TrimSuffix(after, []byte("\r\n")))
	}

	second := dialRDP(t, g.addr())
	payload := []byte("post-redirect rdp traffic")
	sent := append(connectionRequestFor("", inner), payload...)

	if _, err := second.conn.Write(sent); err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	// ── 4. The relay forwards it to the real machine, byte for byte ─────
	waitFor(t, "the target to receive the forwarded stream", func() bool {
		return bytes.Equal(g.win.received(), sent)
	})

	// ── 5. And the audit chain is still intact ──────────────────────────
	if brk, _, err := g.log.Verify(ctx); err != nil || brk != nil {
		t.Fatalf("audit chain broken: %v %v", brk, err)
	}
}

// A wrong code must not produce a redirection, and must not reach the target.
func TestRDPLoginWithWrongCodeIsRefused(t *testing.T) {
	g := startGateway(t, false)

	c := dialRDP(t, g.addr())
	c.negotiate(t, "felix", "")
	c.mcsConnect(t)
	c.sendClientInfo(t, "", "felix", livePassword+",000000")

	// The licence still arrives; a redirection must not.
	lic := c.ioPayload(t)
	if len(lic) < 4 || binary.LittleEndian.Uint16(lic[0:2])&0x0080 == 0 {
		t.Fatalf("expected a licence pdu, got % x", firstBytes(lic))
	}

	// What follows must be a disconnect, never a redirection. The disconnect
	// is deliberate: it lets the client show a real message instead of a
	// dropped socket.
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	body, err := c.readTPKT()
	if err == nil {
		if len(body) < 4 {
			t.Fatalf("unexpected reply of %d bytes", len(body))
		}
		// Past the X.224 data header: an MCS Disconnect Provider Ultimatum.
		if got := body[3] &^ 0x03; got != 0x20 {
			t.Fatalf("server sent 0x%02x after a failed code, want a disconnect", got)
		}
	}

	// Whatever was said, nothing may have reached the machine.
	if len(g.win.received()) != 0 {
		t.Fatal("the target received bytes despite a failed login")
	}

	// And no grant may exist for this address.
	if d := g.engineAuthorize(t); d {
		t.Fatal("a grant was issued despite the second factor failing")
	}
}

// A token that was already spent must not open a second session.
func TestRoutingTokenCannotBeReplayed(t *testing.T) {
	g := startGateway(t, false)

	c := dialRDP(t, g.addr())
	c.negotiate(t, "felix", "")
	c.mcsConnect(t)
	c.sendClientInfo(t, "", "felix", livePassword+","+g.code(t))

	token, _, _ := c.readRedirection(t)
	inner := token
	if after, ok := bytes.CutPrefix([]byte(token), []byte("Cookie: msts=")); ok {
		inner = string(bytes.TrimSuffix(after, []byte("\r\n")))
	}

	first := dialRDP(t, g.addr())
	first.conn.Write(connectionRequestFor("", inner))
	waitFor(t, "the first reconnect to be forwarded", func() bool {
		return len(g.win.received()) > 0
	})
	before := len(g.win.received())

	// Same token again, from a fresh connection.
	second := dialRDP(t, g.addr())
	second.conn.Write(connectionRequestFor("", inner))
	time.Sleep(700 * time.Millisecond)

	if len(g.win.received()) != before {
		t.Fatal("a spent routing token opened a second session")
	}
}

// engineAuthorize reports whether a grant exists for the loopback address the
// test connects from.
func (g *liveGateway) engineAuthorize(t *testing.T) bool {
	t.Helper()

	_, err := g.db.ActiveGrant(context.Background(), "127.0.0.1", time.Now())
	return err == nil
}

func aliveAt(w *fakeWindows) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(w.port())), 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

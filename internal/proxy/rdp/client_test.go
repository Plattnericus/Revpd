package rdp

// A minimal RDP client, only for tests. It walks the same connection sequence
// mstsc does, which is what lets us prove the server side end to end without
// a Windows box in the loop.
//
// This is not proof of interoperability with the real client — only a capture
// against mstsc gives that. It does prove the sequence completes, the field
// layouts are self-consistent and the credentials survive the round trip.

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type testClient struct {
	conn net.Conn
	tls  *tls.Conn
	r    *bufio.Reader

	userID   uint16
	channels []uint16
}

func dialTestClient(addr string) (*testClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return &testClient{conn: conn, r: bufio.NewReader(conn)}, nil
}

func (c *testClient) close() { c.conn.Close() }

// connectionRequest builds an X.224 CR offering TLS, the way mstsc does.
func buildConnectionRequest(cookie string, protocols uint32) []byte {
	var variable []byte
	if cookie != "" {
		variable = append(variable, []byte("Cookie: mstshash="+cookie+"\r\n")...)
	}
	// rdpNegReq: type, flags, length, requestedProtocols.
	variable = append(variable, negTypeRequest, 0x00, 0x08, 0x00)
	variable = append(variable, le32(protocols)...)

	body := make([]byte, 7)
	body[0] = byte(6 + len(variable))
	body[1] = 0xE0
	body = append(body, variable...)

	pkt := make([]byte, 4, 4+len(body))
	pkt[0] = 3
	binary.BigEndian.PutUint16(pkt[2:4], uint16(4+len(body)))
	return append(pkt, body...)
}

// handshake performs the X.224 exchange and starts TLS.
func (c *testClient) handshake(cookie string, protocols uint32) (selected uint32, err error) {
	if _, err := c.conn.Write(buildConnectionRequest(cookie, protocols)); err != nil {
		return 0, err
	}

	body, err := readTPKT(c.r)
	if err != nil {
		return 0, err
	}
	if len(body) < 15 {
		return 0, fmt.Errorf("connection confirm is %d bytes", len(body))
	}
	if body[1] != 0xD0 {
		return 0, fmt.Errorf("expected a CC tpdu, got 0x%02x", body[1])
	}

	switch body[7] {
	case negTypeRsp:
		return binary.LittleEndian.Uint32(body[11:15]), nil
	case negTypeFailure:
		return 0, fmt.Errorf("negotiation failed with code %d", binary.LittleEndian.Uint32(body[11:15]))
	default:
		return 0, fmt.Errorf("unexpected negotiation type 0x%02x", body[7])
	}
}

func (c *testClient) startTLS() error {
	c.tls = tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
	if err := c.tls.Handshake(); err != nil {
		return err
	}
	c.r = bufio.NewReader(c.tls)
	return nil
}

func (c *testClient) writeData(payload []byte) error {
	out := make([]byte, 0, 3+len(payload))
	out = append(out, 0x02, 0xF0, 0x80)
	out = append(out, payload...)
	return writeTPKT(c.tls, out)
}

func (c *testClient) readData() ([]byte, error) {
	body, err := readTPKT(c.r)
	if err != nil {
		return nil, err
	}
	if len(body) < 3 {
		return nil, fmt.Errorf("data tpdu is %d bytes", len(body))
	}
	return body[3:], nil
}

/* --------------------------------------------------- mcs connect initial --- */

// buildTestConnectInitial assembles a Connect Initial with the client data
// blocks a real client sends.
func buildTestConnectInitial(channelNames []string, requestedProtocols uint32) []byte {
	// CS_CORE: 128 bytes up to serverSelectedProtocol, then the protocol field.
	core := make([]byte, 128)
	binary.LittleEndian.PutUint32(core[0:4], 0x00080004) // version
	binary.LittleEndian.PutUint16(core[4:6], 1920)       // desktopWidth
	binary.LittleEndian.PutUint16(core[6:8], 1080)       // desktopHeight
	core = append(core, le32(requestedProtocols)...)

	// CS_NET: channel count then the definitions.
	net := le32(uint32(len(channelNames)))
	for _, n := range channelNames {
		name := make([]byte, 8)
		copy(name, n)
		net = append(net, name...)
		net = append(net, le32(0)...) // options
	}

	userData := append(block(csCore, core), block(csNet, net)...)

	// GCC Conference Create Request.
	gcc := &perWriter{}
	gcc.choice(0)
	gcc.objectIdentifier()
	gcc.length(len(userData) + 14)
	gcc.choice(0xC1)
	gcc.selection(0x08)
	gcc.numericString("1", 1)
	gcc.padding(1)
	gcc.numberOfSets(1)
	gcc.choice(0xC0)
	gcc.octetString(h221ClientToServer, 4)
	gcc.octetString(userData, 0)

	// BER Connect Initial.
	inner := &berWriter{}
	inner.octetString([]byte{0x01}) // callingDomainSelector
	inner.octetString([]byte{0x01}) // calledDomainSelector
	inner.boolean(true)             // upwardFlag
	inner.tagged(berTagDomainParams, domainParameters())
	inner.tagged(berTagDomainParams, domainParameters())
	inner.tagged(berTagDomainParams, domainParameters())
	inner.octetString(gcc.buf)

	outer := &berWriter{}
	outer.application(berTagConnectInitial, inner.buf)
	return outer.buf
}

// mcsConnect runs the MCS phase and records the channels the server assigned.
func (c *testClient) mcsConnect(channelNames []string, protocols uint32) error {
	if err := c.writeData(buildTestConnectInitial(channelNames, protocols)); err != nil {
		return err
	}

	resp, err := c.readData()
	if err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}
	ids, err := parseTestConnectResponse(resp)
	if err != nil {
		return err
	}
	c.channels = ids

	// Erect Domain Request: choice, subHeight, subInterval.
	if err := c.writeData([]byte{mcsErectDomainRequest, 0x01, 0x00, 0x01, 0x00}); err != nil {
		return err
	}

	// Attach User.
	if err := c.writeData([]byte{mcsAttachUserRequest}); err != nil {
		return err
	}
	confirm, err := c.readData()
	if err != nil {
		return fmt.Errorf("read attach user confirm: %w", err)
	}
	if len(confirm) < 4 || domainPDUType(confirm) != mcsAttachUserConfirm {
		return fmt.Errorf("expected attach user confirm, got 0x%02x", safeAt(confirm, 0))
	}
	c.userID = binary.BigEndian.Uint16(confirm[2:4]) + mcsServerChannel

	// Join every channel the server named.
	for _, ch := range c.channels {
		req := &perWriter{}
		req.choice(mcsChannelJoinRequest)
		req.integer16(c.userID, mcsServerChannel)
		req.u16be(ch)

		if err := c.writeData(req.buf); err != nil {
			return err
		}
		got, err := c.readData()
		if err != nil {
			return fmt.Errorf("read channel join confirm for %d: %w", ch, err)
		}
		if domainPDUType(got) != mcsChannelJoinConfirm {
			return fmt.Errorf("expected channel join confirm, got 0x%02x", safeAt(got, 0))
		}
	}
	return nil
}

// parseTestConnectResponse pulls the assigned channel ids back out.
func parseTestConnectResponse(body []byte) ([]uint16, error) {
	cur := &cursor{b: body}
	r := &berReader{c: cur}

	r.expectApplication(berTagConnectResponse)
	r.skipValue() // result
	r.skipValue() // calledConnectId
	r.skipValue() // domainParameters
	userData := r.octetString()
	if err := r.err(); err != nil {
		return nil, err
	}

	idx := indexOf(userData, h221ServerToClient)
	if idx < 0 {
		return nil, fmt.Errorf("connect response has no McDn key")
	}
	c2 := &cursor{b: userData, pos: idx + 4}
	pr := &perReader{c: c2}
	n := pr.length()
	blocks := c2.take(n)
	if c2.err != nil {
		return nil, c2.err
	}

	// Walk the server blocks looking for SC_NET.
	bc := &cursor{b: blocks}
	for bc.remaining() >= 4 {
		t := bc.u16le()
		l := int(bc.u16le())
		if l < 4 || l-4 > bc.remaining() {
			return nil, fmt.Errorf("server block 0x%04x has bad length %d", t, l)
		}
		body := &cursor{b: bc.take(l - 4)}

		if t == scNet {
			io := body.u16le()
			count := int(body.u16le())
			out := []uint16{io}
			for i := 0; i < count; i++ {
				out = append(out, body.u16le())
			}
			return out, body.err
		}
	}
	return nil, fmt.Errorf("connect response has no SC_NET block")
}

/* -------------------------------------------------------- client info --- */

// sendClientInfo builds and sends the PDU carrying the credentials.
func (c *testClient) sendClientInfo(domain, username, password string) error {
	d := utf16le(domain)
	u := utf16le(username)
	p := utf16le(password)

	info := make([]byte, 0, 64+len(d)+len(u)+len(p))
	info = append(info, le16(secInfoPkt)...)
	info = append(info, le16(0)...) // flagsHi

	info = append(info, le32(0)...)           // CodePage
	info = append(info, le32(infoUnicode)...) // flags

	info = append(info, le16(uint16(len(d)))...)
	info = append(info, le16(uint16(len(u)))...)
	info = append(info, le16(uint16(len(p)))...)
	info = append(info, le16(0)...) // cbAlternateShell
	info = append(info, le16(0)...) // cbWorkingDir

	info = append(info, append(d, 0, 0)...)
	info = append(info, append(u, 0, 0)...)
	info = append(info, append(p, 0, 0)...)
	info = append(info, 0, 0) // AlternateShell
	info = append(info, 0, 0) // WorkingDir

	// Client to server is a Send Data Request; the indication goes the other way.
	return c.writeData(buildSendDataRequest(c.userID, mcsIOChannel, info))
}

// readIOPayload reads the next data PDU on the I/O channel.
func (c *testClient) readIOPayload() ([]byte, error) {
	for i := 0; i < 16; i++ {
		body, err := c.readData()
		if err != nil {
			return nil, err
		}
		if domainPDUType(body) != mcsSendDataIndication {
			continue
		}
		// Send Data Indication has the same shape as the request.
		_, payload, err := parseSendDataRequest(body)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no io payload arrived")
}

// receivedRedirection is what the client learned from the redirection PDU.
type receivedRedirection struct {
	flags     uint32
	token     string
	username  string
	domain    string
	password  string
	sessionID uint32
}

// expectLicense consumes the licence PDU that follows the Client Info PDU.
//
// A real client knows this one is coming because of where it is in the
// connection sequence, not by sniffing the bytes — the first two bytes of a
// licence PDU are security flags, while in a share-control PDU they are a
// length. Guessing between them breaks as soon as a length happens to have
// the wrong bit set.
func (c *testClient) expectLicense() error {
	payload, err := c.readIOPayload()
	if err != nil {
		return err
	}
	if len(payload) < 4 {
		return fmt.Errorf("licence pdu is %d bytes", len(payload))
	}
	if flags := binary.LittleEndian.Uint16(payload[0:2]); flags&secLicensePkt == 0 {
		return fmt.Errorf("expected a licence pdu, security flags 0x%04x", flags)
	}
	if got := binary.LittleEndian.Uint32(payload[8:12]); got != statusValidClient {
		return fmt.Errorf("licence error code 0x%08x, want STATUS_VALID_CLIENT", got)
	}
	return nil
}

// readRedirection reads the redirection PDU. Call it after expectLicense.
func (c *testClient) readRedirection() (*receivedRedirection, error) {
	payload, err := c.readIOPayload()
	if err != nil {
		return nil, err
	}
	if len(payload) < 9 {
		return nil, fmt.Errorf("redirection pdu is %d bytes", len(payload))
	}

	// Share Control Header: totalLength(2), pduType(2), PDUSource(2).
	if total := int(binary.LittleEndian.Uint16(payload[0:2])); total != len(payload) {
		return nil, fmt.Errorf("share control header says %d bytes, payload is %d", total, len(payload))
	}
	if t := binary.LittleEndian.Uint16(payload[2:4]) & 0x000F; t != pduTypeServerRedirect {
		return nil, fmt.Errorf("pdu type 0x%04x, want a server redirection", t)
	}

	// Past the header and pad2Octets.
	return parseRedirectionPacket(payload[8:])
}

func parseRedirectionPacket(b []byte) (*receivedRedirection, error) {
	c := &cursor{b: b}

	flags := c.u16le()
	if flags&secRedirectionPkt == 0 {
		return nil, fmt.Errorf("not a redirection packet, flags 0x%04x", flags)
	}
	c.skip(2) // length

	out := &receivedRedirection{sessionID: c.u32le()}
	out.flags = c.u32le()
	if c.err != nil {
		return nil, c.err
	}

	field := func() []byte {
		n := int(c.u32le())
		if c.err != nil || n < 0 || n > c.remaining() {
			c.fail("redirection field of %d bytes does not fit", n)
			return nil
		}
		return c.take(n)
	}

	if out.flags&lbLoadBalanceInfo != 0 {
		out.token = string(field())
	}
	if out.flags&lbUsername != 0 {
		out.username = decodeUTF16(field())
	}
	if out.flags&lbDomain != 0 {
		out.domain = decodeUTF16(field())
	}
	if out.flags&lbPassword != 0 {
		out.password = decodeUTF16(field())
	}
	return out, c.err
}

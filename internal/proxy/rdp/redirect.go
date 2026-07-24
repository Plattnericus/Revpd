package rdp

// Server Redirection, MS-RDPBCGR 2.2.13. This is what makes the whole design
// work: after the second factor checks out we tell the client to reconnect,
// and it does so on its own, carrying a token we recognise.

// RedirFlags, MS-RDPBCGR 2.2.13.1.
const (
	lbTargetNetAddress  uint32 = 0x00000001
	lbLoadBalanceInfo   uint32 = 0x00000002
	lbUsername          uint32 = 0x00000004
	lbDomain            uint32 = 0x00000008
	lbPassword          uint32 = 0x00000010
	lbDontStoreUsername uint32 = 0x00000020
	lbNoRedirect        uint32 = 0x00000080
	lbTargetFQDN        uint32 = 0x00000100
)

// Share Control Header PDU types, MS-RDPBCGR 2.2.8.1.1.1.1.
const (
	pduTypeServerRedirect uint16 = 0x000A
	pduVersion1           uint16 = 0x0010
)

// Redirection describes where to send the client and what to log in with.
type Redirection struct {
	SessionID uint32

	// Token is handed back to us verbatim in the routing token of the next
	// connection. Leaving TargetAddress empty means the client reconnects to
	// the address it already used — our gateway — which is exactly what we
	// want: we stay in the path and proxy to the real machine.
	Token string

	// Credentials for the target. Filled in only for the pass-through mode,
	// so Windows logs the user in without asking a second time.
	Username string
	Domain   string
	Password string
}

// routingToken formats the token the way an RDP client emits it in the next
// X.224 connection request. The trailing CRLF is part of the field.
//
// internal/proxy/x224 parses exactly this shape back out.
func routingToken(token string) []byte {
	return []byte("Cookie: msts=" + token + "\r\n")
}

// buildRedirectionPacket assembles RDP_SERVER_REDIRECTION_PACKET.
func buildRedirectionPacket(r Redirection) []byte {
	var flags uint32
	var fields []byte

	// Field order is fixed by the spec; the flags say which ones are present.
	if r.Token != "" {
		flags |= lbLoadBalanceInfo
	}
	if r.Username != "" {
		flags |= lbUsername
	}
	if r.Domain != "" {
		flags |= lbDomain
	}
	if r.Password != "" {
		flags |= lbPassword
		// The client should not cache what we just handed it.
		flags |= lbDontStoreUsername
	}

	if flags&lbLoadBalanceInfo != 0 {
		fields = append(fields, lengthPrefixed(routingToken(r.Token))...)
	}
	if flags&lbUsername != 0 {
		fields = append(fields, lengthPrefixed(utf16leZ(r.Username))...)
	}
	if flags&lbDomain != 0 {
		fields = append(fields, lengthPrefixed(utf16leZ(r.Domain))...)
	}
	if flags&lbPassword != 0 {
		fields = append(fields, lengthPrefixed(utf16leZ(r.Password))...)
	}

	// Flags(2) + Length(2) + SessionID(4) + RedirFlags(4) + the fields.
	total := 12 + len(fields)

	out := make([]byte, 0, total)
	out = append(out, le16(secRedirectionPkt)...)
	out = append(out, le16(uint16(total))...)
	out = append(out, le32(r.SessionID)...)
	out = append(out, le32(flags)...)
	out = append(out, fields...)

	return out
}

// lengthPrefixed writes a 4-byte little-endian length followed by the data,
// which is how every variable field in the redirection packet is framed.
func lengthPrefixed(b []byte) []byte {
	out := make([]byte, 0, 4+len(b))
	out = append(out, le32(uint32(len(b)))...)
	return append(out, b...)
}

// buildRedirectionPDU wraps the packet in the Share Control Header the client
// looks for. MS-RDPBCGR 2.2.13.3, enhanced security variant — no security
// header, because TLS already protects the channel.
func buildRedirectionPDU(userID uint16, r Redirection) []byte {
	packet := buildRedirectionPacket(r)

	// shareControlHeader(6) + pad2Octets(2) + packet + pad1Octet(1)
	total := 6 + 2 + len(packet) + 1

	out := make([]byte, 0, total)
	out = append(out, le16(uint16(total))...)
	out = append(out, le16(pduVersion1|pduTypeServerRedirect)...)
	out = append(out, le16(userID)...)
	out = append(out, 0x00, 0x00) // pad2Octets
	out = append(out, packet...)
	out = append(out, 0x00) // pad1Octet

	return out
}

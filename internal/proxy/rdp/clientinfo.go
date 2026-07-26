package rdp

import "strings"

// Basic security header flags, MS-RDPBCGR 2.2.8.1.1.2.1.
const (
	secExchangePkt    uint16 = 0x0001
	secEncrypt        uint16 = 0x0008
	secInfoPkt        uint16 = 0x0040
	secLicensePkt     uint16 = 0x0080
	secRedirectionPkt uint16 = 0x0400
)

// TS_INFO_PACKET flags, MS-RDPBCGR 2.2.1.11.1.1.
const (
	infoUnicode uint32 = 0x00000010
)

// Credentials are what the client sent in its Client Info PDU.
//
// Password is the raw field. It still carries the MFA suffix at this point;
// splitting happens in SplitPassword.
type Credentials struct {
	Domain   string
	Username string
	Password string
}

// parseClientInfo reads a Client Info PDU payload, i.e. what came out of the
// MCS data PDU.
//
// The password lives in memory for the length of one login and is never
// written anywhere. Callers must keep it that way.
func parseClientInfo(payload []byte) (*Credentials, error) {
	c := &cursor{b: payload}

	// Basic security header.
	flags := c.u16le()
	c.skip(2) // flagsHi
	if c.err != nil {
		return nil, c.err
	}
	if flags&secInfoPkt == 0 {
		return nil, fmtErr("expected a client info pdu, security flags 0x%04x", flags)
	}
	if flags&secEncrypt != 0 {
		// Only possible if we had negotiated legacy RDP encryption, which we
		// never do. Refuse rather than hand back garbage.
		return nil, fmtErr("client info pdu is encrypted; TLS was expected to carry it")
	}

	c.skip(4) // CodePage
	infoFlags := c.u32le()

	cbDomain := int(c.u16le())
	cbUserName := int(c.u16le())
	cbPassword := int(c.u16le())
	cbAltShell := int(c.u16le())
	cbWorkingDir := int(c.u16le())
	if c.err != nil {
		return nil, c.err
	}

	unicode := infoFlags&infoUnicode != 0

	// The cb fields exclude the terminator; the field on the wire includes it.
	term := 1
	if unicode {
		term = 2
	}

	read := func(cb int) string {
		if cb < 0 || cb > 8192 {
			c.fail("string field of %d bytes is implausible", cb)
			return ""
		}
		raw := c.take(cb + term)
		if c.err != nil {
			return ""
		}
		if unicode {
			return decodeUTF16(raw)
		}
		return trimZero(string(raw))
	}

	domain := read(cbDomain)
	username := read(cbUserName)
	password := read(cbPassword)

	// AlternateShell and WorkingDir follow but tell us nothing useful.
	_ = cbAltShell
	_ = cbWorkingDir

	if c.err != nil {
		return nil, c.err
	}
	if username == "" {
		return nil, fmtErr("client info pdu carries no username")
	}

	return &Credentials{Domain: domain, Username: username, Password: password}, nil
}

// SplitPassword separates the real password from the MFA suffix.
//
// Windows passwords may contain commas, so the split is on the LAST one. That
// is the same convention Duo uses, and it is what the README documents:
//
//	MyPassword,123456        one-time code
//	MyPassword,push          push approval
//	MyPassword,K7RM2-9XQPD   backup code
//
// Without a comma the whole string is the password and the second factor is
// empty, which the caller must treat as a failed login rather than a pass.
func SplitPassword(raw string) (password, factor string) {
	i := strings.LastIndex(raw, ",")
	if i < 0 {
		return raw, ""
	}
	return raw[:i], strings.TrimSpace(raw[i+1:])
}

/* -------------------------------------------------------------- licence --- */

// License error codes, MS-RDPBCGR 2.2.1.12.1.3.
const (
	licenseErrorAlert byte   = 0xFF
	licensePreambleV3 byte   = 0x03
	statusValidClient uint32 = 0x00000007
	stateNoTransition uint32 = 0x00000002
	blobTypeError     uint16 = 0x0004
)

// buildLicenseValidClient tells the client no licence is needed.
//
// Skipping this leaves mstsc waiting: it expects either a licence exchange or
// this explicit "you are fine" after sending its Client Info PDU.
func buildLicenseValidClient() []byte {
	const msgSize = 16 // preamble (4) + error message (12)

	out := make([]byte, 0, 4+msgSize)
	out = append(out, le16(secLicensePkt)...)
	out = append(out, le16(0)...) // flagsHi

	out = append(out, licenseErrorAlert, licensePreambleV3)
	out = append(out, le16(msgSize)...)

	out = append(out, le32(statusValidClient)...)
	out = append(out, le32(stateNoTransition)...)
	out = append(out, le16(blobTypeError)...)
	out = append(out, le16(0)...) // empty blob

	return out
}

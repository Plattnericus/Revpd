package rdp

// GCC conference user data: the blocks the client and server exchange inside
// the MCS connect PDUs. MS-RDPBCGR 2.2.1.3 and 2.2.1.4.

// Client-to-server block types.
const (
	csCore     uint16 = 0xC001
	csSecurity uint16 = 0xC002
	csNet      uint16 = 0xC003
	csCluster  uint16 = 0xC004
)

// Server-to-client block types.
const (
	scCore     uint16 = 0x0C01
	scSecurity uint16 = 0x0C02
	scNet      uint16 = 0x0C03
)

// MCS channel identifiers. 1001 is the server, 1002 the first user, 1003 the
// I/O channel that carries the actual RDP stream; virtual channels follow.
const (
	mcsServerChannel  uint16 = 1001
	mcsIOChannel      uint16 = 1003
	mcsFirstVirtualCh uint16 = 1004
)

// clientBlocks is what we need out of the client's user data.
type clientBlocks struct {
	// Names of the virtual channels the client asked for, in order. We do not
	// use them beyond counting, but keeping the names makes logs readable.
	channels []string

	// requestedProtocols is echoed back in SC_CORE so the client can confirm
	// that nobody tampered with the security negotiation.
	requestedProtocols uint32
}

// parseClientBlocks walks the user data blocks. Unknown blocks are skipped:
// clients keep adding new ones and none of them concern us.
func parseClientBlocks(data []byte) (*clientBlocks, error) {
	out := &clientBlocks{channels: []string{}}
	c := &cursor{b: data}

	for c.remaining() >= 4 {
		blockType := c.u16le()
		blockLen := int(c.u16le())
		if c.err != nil {
			return nil, c.err
		}

		// Length covers the 4-byte header too.
		if blockLen < 4 || blockLen-4 > c.remaining() {
			return nil, fmtErr("user data block 0x%04x claims %d bytes, %d left", blockType, blockLen, c.remaining())
		}
		body := &cursor{b: c.take(blockLen - 4)}

		switch blockType {
		case csCore:
			// version(4) desktopWidth(2) desktopHeight(2) colorDepth(2)
			// sasSequence(2) keyboardLayout(4) clientBuild(4) clientName(32)
			// keyboardType(4) keyboardSubType(4) keyboardFuncKey(4)
			// imeFileName(64) postBeta2ColorDepth(2) clientProductId(2)
			// serialNumber(4) highColorDepth(2) supportedColorDepths(2)
			// earlyCapabilityFlags(2) clientDigProductId(64) connectionType(1)
			// pad(1) serverSelectedProtocol(4)
			//
			// Everything from postBeta2ColorDepth on is optional, so read
			// defensively and take the protocol field only if it is there.
			if body.remaining() >= 128+4 {
				body.skip(128)
				if body.remaining() >= 4 {
					out.requestedProtocols = body.u32le()
				}
			}

		case csNet:
			count := int(body.u32le())
			if body.err != nil {
				return nil, body.err
			}
			// Each definition is 8 bytes of name plus 4 of options.
			if count < 0 || count > 31 || count*12 > body.remaining() {
				return nil, fmtErr("client asked for %d virtual channels", count)
			}
			for i := 0; i < count; i++ {
				name := body.take(8)
				body.skip(4) // options
				out.channels = append(out.channels, trimZero(string(name)))
			}

		default:
			// csSecurity, csCluster, monitors, anything newer: not our business.
		}

		if body.err != nil {
			return nil, body.err
		}
	}
	return out, c.err
}

func trimZero(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}

// channelIDs returns the identifiers assigned to the client's channels, in the
// same order it asked for them.
func (cb *clientBlocks) channelIDs() []uint16 {
	ids := make([]uint16, len(cb.channels))
	for i := range cb.channels {
		ids[i] = mcsFirstVirtualCh + uint16(i)
	}
	return ids
}

// buildServerBlocks assembles the user data for the Connect Response.
func buildServerBlocks(cb *clientBlocks, selectedProtocol uint32) []byte {
	var out []byte

	// SC_CORE — MS-RDPBCGR 2.2.1.4.2.
	core := make([]byte, 0, 12)
	core = append(core, le32(0x00080004)...)      // RDP 5.0 and later
	core = append(core, le32(selectedProtocol)...) // echo the negotiated protocol
	core = append(core, le32(0)...)                // earlyCapabilityFlags
	out = append(out, block(scCore, core)...)

	// SC_NET — MS-RDPBCGR 2.2.1.4.4.
	ids := cb.channelIDs()
	net := make([]byte, 0, 4+2*len(ids)+2)
	net = append(net, le16(mcsIOChannel)...)
	net = append(net, le16(uint16(len(ids)))...)
	for _, id := range ids {
		net = append(net, le16(id)...)
	}
	// The block has to end on a 4-byte boundary.
	if len(ids)%2 != 0 {
		net = append(net, 0x00, 0x00)
	}
	out = append(out, block(scNet, net)...)

	// SC_SECURITY — MS-RDPBCGR 2.2.1.4.3.
	//
	// Both fields zero because TLS already protects the channel. That also
	// means no server random and no certificate need to follow.
	sec := make([]byte, 0, 8)
	sec = append(sec, le32(0)...) // encryptionMethod: none
	sec = append(sec, le32(0)...) // encryptionLevel: none
	out = append(out, block(scSecurity, sec)...)

	return out
}

// block prefixes a body with its type and total length.
func block(t uint16, body []byte) []byte {
	out := make([]byte, 0, 4+len(body))
	out = append(out, le16(t)...)
	out = append(out, le16(uint16(len(body)+4))...)
	return append(out, body...)
}

// buildConferenceCreateResponse wraps the server blocks in the PER envelope
// mstsc expects. See the request side in per.go for the mirror image.
func buildConferenceCreateResponse(userData []byte) []byte {
	w := &perWriter{}

	w.choice(0x14)
	w.objectIdentifier()
	w.length(len(userData) + 14)

	w.choice(0x14)
	w.integer16(0x79F3, 1001) // node id
	w.integer(1)              // tag
	w.enumerated(0)           // result: success
	w.numberOfSets(1)
	w.choice(0xC0)
	w.octetString(h221ServerToClient, 4)
	w.octetString(userData, 0)

	return w.buf
}

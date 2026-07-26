package rdp

// The MCS layer (T.125) as far as the login needs it: connect, hand out a user
// id, confirm the channel joins, then read one data PDU.

// DomainMCSPDU choices, shifted into the top six bits the way PER wants them.
const (
	mcsErectDomainRequest  = 1 << 2  // 0x04
	mcsDisconnectUltimatum = 8 << 2  // 0x20
	mcsAttachUserRequest   = 10 << 2 // 0x28
	mcsAttachUserConfirm   = 11 << 2 // 0x2C
	mcsChannelJoinRequest  = 14 << 2 // 0x38
	mcsChannelJoinConfirm  = 15 << 2 // 0x3C
	mcsSendDataRequest     = 25 << 2 // 0x64
	mcsSendDataIndication  = 26 << 2 // 0x68
)

// Confirm PDUs carry a two-bit option field alongside the choice.
const mcsOptions2 = 0x02

// The user id we hand out. Any value at or above the base channel works.
const mcsUserID uint16 = 1002

/* ------------------------------------------------------ connect initial --- */

// parseConnectInitial extracts the client's GCC user data.
//
// The domain parameters are read past rather than honoured: we never carry a
// real MCS domain, we only need to get to the credentials.
func parseConnectInitial(body []byte) (*clientBlocks, error) {
	c := &cursor{b: body}
	r := &berReader{c: c}

	r.expectApplication(berTagConnectInitial)
	r.skipValue() // callingDomainSelector
	r.skipValue() // calledDomainSelector
	r.skipValue() // upwardFlag
	r.skipValue() // targetParameters
	r.skipValue() // minimumParameters
	r.skipValue() // maximumParameters

	userData := r.octetString()
	if err := r.err(); err != nil {
		return nil, err
	}

	blocks, err := findUserData(userData)
	if err != nil {
		return nil, err
	}
	return parseClientBlocks(blocks)
}

/* ----------------------------------------------------- connect response --- */

// buildConnectResponse assembles the BER reply to Connect Initial.
func buildConnectResponse(cb *clientBlocks, selectedProtocol uint32) []byte {
	gcc := buildConferenceCreateResponse(buildServerBlocks(cb, selectedProtocol))

	inner := &berWriter{}
	inner.enumerated(0) // result: rt-successful
	inner.integer(0)    // calledConnectId
	inner.tagged(berTagDomainParams, domainParameters())
	inner.octetString(gcc)

	outer := &berWriter{}
	outer.application(berTagConnectResponse, inner.buf)
	return outer.buf
}

// domainParameters are the eight integers T.125 expects, in order.
func domainParameters() []byte {
	w := &berWriter{}
	w.integer(34)    // maxChannelIds
	w.integer(3)     // maxUserIds
	w.integer(0)     // maxTokenIds
	w.integer(1)     // numPriorities
	w.integer(0)     // minThroughput
	w.integer(1)     // maxHeight
	w.integer(65535) // maxMCSPDUsize
	w.integer(2)     // protocolVersion
	return w.buf
}

/* --------------------------------------------------------- domain pdus --- */

// domainPDUType returns the choice byte of a PER-encoded domain PDU.
func domainPDUType(body []byte) byte {
	if len(body) == 0 {
		return 0
	}
	// Mask off the option bits so callers can compare against the constants.
	return body[0] &^ 0x03
}

// buildAttachUserConfirm grants the client its user id.
func buildAttachUserConfirm(userID uint16) []byte {
	w := &perWriter{}
	w.choice(mcsAttachUserConfirm | mcsOptions2)
	w.enumerated(0) // result: success
	w.integer16(userID, mcsServerChannel)
	return w.buf
}

// parseChannelJoinRequest reads which channel the client wants to join.
func parseChannelJoinRequest(body []byte) (channelID uint16, err error) {
	c := &cursor{b: body, pos: 1} // skip the choice byte

	if c.remaining() < 4 {
		return 0, fmtErr("channel join request is %d bytes", len(body))
	}
	c.skip(2) // initiator, relative to the base channel id
	hi, lo := c.u8(), c.u8()

	return uint16(hi)<<8 | uint16(lo), c.err
}

// buildChannelJoinConfirm accepts a join. We echo the requested id back
// unchanged, which is what a single-server deployment should do.
func buildChannelJoinConfirm(userID, channelID uint16) []byte {
	w := &perWriter{}
	w.choice(mcsChannelJoinConfirm | mcsOptions2)
	w.enumerated(0) // result: success
	w.integer16(userID, mcsServerChannel)
	w.integer16(channelID, 0) // requested
	w.integer16(channelID, 0) // joined
	return w.buf
}

/* ------------------------------------------------------------ send data --- */

// parseSendDataRequest unwraps an MCS data PDU and returns its payload.
func parseSendDataRequest(body []byte) (channelID uint16, payload []byte, err error) {
	c := &cursor{b: body, pos: 1} // skip the choice byte
	r := &perReader{c: c}

	c.skip(2) // initiator
	hi, lo := c.u8(), c.u8()
	channelID = uint16(hi)<<8 | uint16(lo)

	c.skip(1) // data priority and segmentation flags

	n := r.length()
	if c.err != nil {
		return 0, nil, c.err
	}
	if n < 0 || n > c.remaining() {
		return 0, nil, fmtErr("send data claims %d bytes, %d left", n, c.remaining())
	}
	return channelID, c.take(n), c.err
}

// buildSendDataIndication wraps a payload for the client. Server to client is
// always an indication; the request form travels the other way.
func buildSendDataIndication(userID, channelID uint16, payload []byte) []byte {
	return buildSendData(mcsSendDataIndication, userID, channelID, payload)
}

// buildSendDataRequest is the client-to-server form. Only the test client
// needs it, but keeping both next to each other stops them drifting apart.
func buildSendDataRequest(userID, channelID uint16, payload []byte) []byte {
	return buildSendData(mcsSendDataRequest, userID, channelID, payload)
}

func buildSendData(choice byte, userID, channelID uint16, payload []byte) []byte {
	w := &perWriter{}
	w.choice(choice)
	w.integer16(userID, mcsServerChannel)
	w.u16be(channelID)
	w.u8(0x70) // priority high, no segmentation
	w.length(len(payload))
	w.raw(payload)
	return w.buf
}

// buildDisconnectUltimatum ends the session politely, so the client shows a
// clean message instead of a dropped-connection error.
func buildDisconnectUltimatum(reason byte) []byte {
	w := &perWriter{}
	w.choice(mcsDisconnectUltimatum | 0x01)
	w.enumerated(reason)
	return w.buf
}

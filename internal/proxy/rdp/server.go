package rdp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/plattnericus/revpd/internal/proxy/x224"
)

// Outcome tells the caller how a login attempt ended, without ever carrying
// the reason back to the client in a form that distinguishes cases.
type Outcome string

const (
	OutcomeRedirected Outcome = "redirected"
	OutcomeRejected   Outcome = "rejected"
	OutcomeFailed     Outcome = "failed"
)

// Authenticator turns credentials into a redirection. It owns all policy:
// password check, second factor, Wake-on-LAN and issuing the token.
//
// It must take the same amount of observable time for a wrong password as for
// an unknown account, or the login becomes a user enumeration oracle.
type Authenticator interface {
	Authenticate(ctx context.Context, srcIP net.IP, creds *Credentials) (*Redirection, error)
}

type Options struct {
	// TLSConfig must carry a certificate. mstsc will warn about a self-signed
	// one exactly as it does for a stock Windows host, then connect.
	TLSConfig *tls.Config

	// HandshakeTimeout bounds the whole login sequence. Generous, because a
	// sleeping target has to boot inside it.
	HandshakeTimeout time.Duration

	// StepTimeout bounds a single read, so a client that stalls mid-sequence
	// cannot pin a goroutine.
	StepTimeout time.Duration
}

// Login runs the RDP-native login on an accepted connection.
//
// It takes the connection over completely. When it returns the client has
// either been told to reconnect or been disconnected; either way the caller
// must not keep using conn.
type Login struct {
	opts Options
	auth Authenticator
}

func NewLogin(opts Options, auth Authenticator) *Login {
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 3 * time.Minute
	}
	if opts.StepTimeout == 0 {
		opts.StepTimeout = 30 * time.Second
	}
	return &Login{opts: opts, auth: auth}
}

// Run performs the sequence. cr is the connection request already read off the
// wire by the caller, so this picks up from the X.224 response.
//
// It returns the username that was logged in, for the caller's audit trail.
// The password is never returned and never leaves this function.
func (l *Login) Run(ctx context.Context, conn net.Conn, cr *x224.ConnectionRequest, srcIP net.IP) (string, error) {
	outcome, user, err := l.run(ctx, conn, cr, srcIP)
	if err != nil {
		return user, err
	}
	if outcome != OutcomeRedirected {
		return user, errors.New("login did not complete")
	}
	return user, nil
}

func (l *Login) run(ctx context.Context, conn net.Conn, cr *x224.ConnectionRequest, srcIP net.IP) (Outcome, string, error) {
	ctx, cancel := context.WithTimeout(ctx, l.opts.HandshakeTimeout)
	defer cancel()

	neg := parseNegRequest(crVariablePart(cr.Raw))

	// A client that will not do TLS gets a clear reason rather than a dropped
	// socket. We refuse plain RDP security: the credentials would be protected
	// by RC4 with a known key exchange, which is not good enough here.
	if neg.present && neg.protocols&ProtocolSSL == 0 {
		conn.SetWriteDeadline(time.Now().Add(l.opts.StepTimeout))
		writeNegotiationFailure(conn, failSSLRequiredByServer)
		return OutcomeRejected, "", errors.New("client does not offer TLS")
	}
	if !neg.present {
		conn.SetWriteDeadline(time.Now().Add(l.opts.StepTimeout))
		writeNegotiationFailure(conn, failSSLRequiredByServer)
		return OutcomeRejected, "", errors.New("client offers no security negotiation")
	}

	conn.SetWriteDeadline(time.Now().Add(l.opts.StepTimeout))
	if err := writeConnectionConfirm(conn, ProtocolSSL); err != nil {
		return OutcomeFailed, "", err
	}

	// From here on everything is inside TLS.
	tlsConn := tls.Server(conn, l.opts.TLSConfig)
	conn.SetDeadline(time.Now().Add(l.opts.StepTimeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return OutcomeFailed, "", fmt.Errorf("tls handshake: %w", err)
	}

	s := &session{
		conn:   tlsConn,
		raw:    conn,
		r:      bufio.NewReaderSize(tlsConn, MaxPDU),
		step:   l.opts.StepTimeout,
		userID: mcsUserID,
	}

	creds, err := s.negotiate(ProtocolSSL)
	if err != nil {
		return OutcomeFailed, "", err
	}

	user := creds.Username
	defer func() {
		// The password must not outlive the login. Go strings cannot be
		// scrubbed, so at least drop the reference promptly.
		creds.Password = ""
	}()

	redir, err := l.auth.Authenticate(ctx, srcIP, creds)
	if err != nil {
		// Never say why. A prober must not learn whether the account exists,
		// the password was wrong or the second factor failed.
		s.disconnect()
		return OutcomeRejected, user, err
	}
	if redir == nil {
		s.disconnect()
		return OutcomeRejected, user, errors.New("authenticator returned no redirection")
	}

	if err := s.sendRedirection(*redir); err != nil {
		return OutcomeFailed, user, err
	}

	slog.Info("client redirected", "src", srcIP, "user", user)
	return OutcomeRedirected, user, nil
}

// crVariablePart returns everything after the fixed 11-byte header of a
// connection request, which is where the cookie and rdpNegReq live.
func crVariablePart(raw []byte) []byte {
	const fixed = 4 + 7
	if len(raw) <= fixed {
		return nil
	}
	return raw[fixed:]
}

/* -------------------------------------------------------------- session --- */

type session struct {
	conn   net.Conn // the TLS connection
	raw    net.Conn // the socket underneath, for deadlines
	r      *bufio.Reader
	step   time.Duration
	userID uint16

	channels []uint16
}

func (s *session) deadline() {
	s.raw.SetDeadline(time.Now().Add(s.step))
}

func (s *session) read() ([]byte, error) {
	s.deadline()
	return readTPKT(s.r)
}

func (s *session) write(payload []byte) error {
	s.deadline()
	return writeTPKT(s.conn, payload)
}

// writeX224Data wraps a payload in an X.224 data TPDU, which everything after
// the connection phase travels in.
func (s *session) writeX224Data(payload []byte) error {
	out := make([]byte, 0, 3+len(payload))
	out = append(out, 0x02, 0xF0, 0x80) // length indicator, DT TPDU, EOT
	out = append(out, payload...)
	return s.write(out)
}

// readX224Data strips the data TPDU header.
func (s *session) readX224Data() ([]byte, error) {
	body, err := s.read()
	if err != nil {
		return nil, err
	}
	if len(body) < 3 || body[1] != 0xF0 {
		return nil, fmtErr("expected an x.224 data tpdu, got 0x%02x", safeAt(body, 1))
	}
	return body[3:], nil
}

func safeAt(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}

// negotiate walks the connection sequence up to the Client Info PDU.
func (s *session) negotiate(selectedProtocol uint32) (*Credentials, error) {
	// MCS Connect Initial.
	body, err := s.read()
	if err != nil {
		return nil, fmt.Errorf("read connect initial: %w", err)
	}
	if len(body) < 3 || body[1] != 0xF0 {
		return nil, fmtErr("expected connect initial in a data tpdu")
	}

	blocks, err := parseConnectInitial(body[3:])
	if err != nil {
		return nil, fmt.Errorf("parse connect initial: %w", err)
	}
	s.channels = append([]uint16{mcsIOChannel}, blocks.channelIDs()...)

	if err := s.writeX224Data(buildConnectResponse(blocks, selectedProtocol)); err != nil {
		return nil, fmt.Errorf("write connect response: %w", err)
	}

	// The rest of the sequence is a short state machine. Bound the number of
	// PDUs so a client cannot loop us forever.
	joined := 0
	for i := 0; i < 64; i++ {
		payload, err := s.readX224Data()
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			continue
		}

		switch domainPDUType(payload) {
		case mcsErectDomainRequest:
			// Nothing to answer.

		case mcsAttachUserRequest:
			if err := s.writeX224Data(buildAttachUserConfirm(s.userID)); err != nil {
				return nil, fmt.Errorf("write attach user confirm: %w", err)
			}

		case mcsChannelJoinRequest:
			ch, err := parseChannelJoinRequest(payload)
			if err != nil {
				return nil, err
			}
			if err := s.writeX224Data(buildChannelJoinConfirm(s.userID, ch)); err != nil {
				return nil, fmt.Errorf("write channel join confirm: %w", err)
			}
			joined++

		case mcsSendDataRequest:
			ch, data, err := parseSendDataRequest(payload)
			if err != nil {
				return nil, err
			}
			if ch != mcsIOChannel || len(data) < 4 {
				continue
			}

			flags := uint16(data[0]) | uint16(data[1])<<8
			switch {
			case flags&secInfoPkt != 0:
				creds, err := parseClientInfo(data)
				if err != nil {
					return nil, err
				}
				// Tell the client it needs no licence, otherwise it waits.
				if err := s.sendOnIO(buildLicenseValidClient()); err != nil {
					return nil, fmt.Errorf("write license response: %w", err)
				}
				return creds, nil

			case flags&secExchangePkt != 0:
				// Only sent when legacy RDP encryption was negotiated. We
				// never negotiate it, so this means a confused client.
				return nil, fmtErr("client sent a security exchange despite TLS")
			}

		case mcsDisconnectUltimatum:
			return nil, errors.New("client disconnected during the login sequence")
		}

		_ = joined
	}
	return nil, fmtErr("client never sent its credentials")
}

// sendOnIO wraps a payload for the I/O channel and sends it.
func (s *session) sendOnIO(payload []byte) error {
	return s.writeX224Data(buildSendDataIndication(s.userID, mcsIOChannel, payload))
}

func (s *session) sendRedirection(r Redirection) error {
	if err := s.sendOnIO(buildRedirectionPDU(s.userID, r)); err != nil {
		return fmt.Errorf("write redirection: %w", err)
	}
	// Give the client a moment to act on it before the socket goes away.
	time.Sleep(100 * time.Millisecond)
	return nil
}

// disconnect ends the session so the client shows a proper message.
func (s *session) disconnect() {
	s.writeX224Data(buildDisconnectUltimatum(1)) // 1 = user requested
}

// Package duo talks to the Duo Auth API v2.
//
// Only what an approval needs: check the integration works, send a push, and
// wait for the person to tap it. Enrolment and device management stay in the
// Duo admin panel.
//
// Requests are signed the way Duo specifies: an HMAC-SHA1 over a canonical
// string, sent as HTTP Basic auth with the integration key as the username.
package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotConfigured = errors.New("duo is not configured")
	ErrDenied        = errors.New("the request was declined")
	ErrNoDevice      = errors.New("the account has no device that can approve")
)

type Client struct {
	apiHost string
	ikey    string
	skey    string

	http *http.Client

	// Poll is how often we ask Duo whether the person has answered. Duo's
	// auth_status long-polls for up to ~30s, so this is a fallback, not a spin.
	Poll time.Duration
}

type Options struct {
	APIHost string
	IKey    string
	SKey    string
	Timeout time.Duration
}

// New returns nil when Duo is not configured, which callers treat as
// "push is unavailable" rather than an error.
func New(o Options) *Client {
	if o.APIHost == "" || o.IKey == "" || o.SKey == "" {
		return nil
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}

	return &Client{
		apiHost: strings.TrimPrefix(strings.TrimPrefix(o.APIHost, "https://"), "http://"),
		ikey:    o.IKey,
		skey:    o.SKey,
		http:    &http.Client{Timeout: o.Timeout},
		Poll:    2 * time.Second,
	}
}

// Configured is a nil-safe check, so callers do not have to nil-test a client.
func (c *Client) Configured() bool { return c != nil }

/* ------------------------------------------------------------- signing --- */

// canonical builds the string Duo signs: date, method, host, path and the
// sorted parameters, joined with newlines.
//
// Getting the order or the escaping wrong yields a bare 40103 from Duo with no
// further explanation, so this mirrors the spec literally. The date is passed
// in rather than formatted here, because the same string has to go into the
// Date header — signing one spelling and sending another is the other way to
// earn a 40103.
func (c *Client) canonical(date, method, path string, params url.Values) string {
	return strings.Join([]string{
		date,
		strings.ToUpper(method),
		strings.ToLower(c.apiHost),
		path,
		encodeParams(params),
	}, "\n")
}

func (c *Client) signature(canon string) string {
	mac := hmac.New(sha1.New, []byte(c.skey))
	mac.Write([]byte(canon))
	return hex.EncodeToString(mac.Sum(nil))
}

// sign builds the Authorization and Date headers for a request.
func (c *Client) sign(method, path string, params url.Values, now time.Time) (auth, date string) {
	date = now.UTC().Format(time.RFC1123Z)
	return basicAuth(c.ikey, c.signature(c.canonical(date, method, path, params))), date
}

// encodeParams sorts by key and escapes the way Duo expects. url.Values.Encode
// already sorts and uses RFC 3986 escaping apart from the space, which Duo
// wants as %20 rather than +.
func encodeParams(params url.Values) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, escape(k)+"="+escape(v))
		}
	}
	return strings.Join(parts, "&")
}

func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func basicAuth(user, pass string) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	raw := user + ":" + pass
	var out strings.Builder
	for i := 0; i < len(raw); i += 3 {
		var n uint32
		rem := len(raw) - i
		n = uint32(raw[i]) << 16
		if rem > 1 {
			n |= uint32(raw[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(raw[i+2])
		}
		out.WriteByte(b64[(n>>18)&0x3F])
		out.WriteByte(b64[(n>>12)&0x3F])
		if rem > 1 {
			out.WriteByte(b64[(n>>6)&0x3F])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(b64[n&0x3F])
		} else {
			out.WriteByte('=')
		}
	}
	return "Basic " + out.String()
}

/* ------------------------------------------------------------ requests --- */

type response struct {
	Stat     string          `json:"stat"`
	Response json.RawMessage `json:"response"`
	Code     int             `json:"code"`
	Message  string          `json:"message"`
	Detail   string          `json:"message_detail"`
}

func (c *Client) call(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}

	auth, date := c.sign(method, path, params, time.Now())
	endpoint := "https://" + c.apiHost + path

	var req *http.Request
	var err error

	if method == http.MethodGet {
		if len(params) > 0 {
			endpoint += "?" + encodeParams(params)
		}
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(encodeParams(params)))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("build duo request: %w", err)
	}

	req.Header.Set("Authorization", auth)
	req.Header.Set("Date", date)
	req.Header.Set("Host", c.apiHost)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call duo: %w", err)
	}
	defer resp.Body.Close()

	// Cap the body: a confused endpoint should not be able to exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read duo response: %w", err)
	}

	var out response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("duo returned %d with an unreadable body", resp.StatusCode)
	}
	if out.Stat != "OK" {
		// The message is safe to log; it never contains the secret key.
		return nil, fmt.Errorf("duo error %d: %s %s", out.Code, out.Message, out.Detail)
	}
	return out.Response, nil
}

// Check verifies the credentials and that the clock is close enough. Duo
// rejects requests whose Date is more than a few minutes off.
func (c *Client) Check(ctx context.Context) error {
	_, err := c.call(ctx, http.MethodGet, "/auth/v2/check", nil)
	return err
}

/* ------------------------------------------------------------- approve --- */

// Approve sends a push and blocks until the person answers, the context
// expires, or Duo gives up.
//
// It implements policy.Approver.
func (c *Client) Approve(ctx context.Context, username, srcIP, target string) (bool, error) {
	if !c.Configured() {
		return false, ErrNotConfigured
	}

	params := url.Values{}
	params.Set("username", username)
	params.Set("factor", "push")
	params.Set("device", "auto")
	params.Set("async", "1")

	// Shown on the phone, so the person can tell a real attempt from someone
	// else's. Duo renders these as extra lines under the prompt.
	params.Set("type", "Remote Desktop")
	if srcIP != "" {
		params.Set("pushinfo", "from="+url.QueryEscape(srcIP)+"&to="+url.QueryEscape(orDash(target)))
	}
	if srcIP != "" {
		params.Set("ipaddr", srcIP)
	}

	raw, err := c.call(ctx, http.MethodPost, "/auth/v2/auth", params)
	if err != nil {
		return false, err
	}

	var started struct {
		TxID   string `json:"txid"`
		Result string `json:"result"`
		Status string `json:"status_msg"`
	}
	if err := json.Unmarshal(raw, &started); err != nil {
		return false, fmt.Errorf("duo returned an unreadable auth response: %w", err)
	}

	// A synchronous denial can come straight back, e.g. no enrolled device.
	if started.TxID == "" {
		switch started.Result {
		case "allow":
			return true, nil
		case "deny":
			return false, ErrDenied
		default:
			return false, fmt.Errorf("duo did not start a transaction: %s", started.Status)
		}
	}

	return c.wait(ctx, started.TxID)
}

// wait polls auth_status until Duo reports an outcome.
func (c *Client) wait(ctx context.Context, txid string) (bool, error) {
	params := url.Values{}
	params.Set("txid", txid)

	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		raw, err := c.call(ctx, http.MethodGet, "/auth/v2/auth_status", params)
		if err != nil {
			// The context expiring here is the hold timeout, not a Duo fault.
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, err
		}

		var st struct {
			Result string `json:"result"`
			Status string `json:"status"`
			Msg    string `json:"status_msg"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			return false, fmt.Errorf("duo returned an unreadable status: %w", err)
		}

		switch st.Result {
		case "allow":
			return true, nil
		case "deny":
			slog.Info("duo push declined", "status", st.Status)
			return false, ErrDenied
		case "waiting", "":
			// auth_status long-polls, so this loops rarely. The pause is only
			// there so a misbehaving endpoint cannot spin us.
			select {
			case <-time.After(c.Poll):
			case <-ctx.Done():
				return false, ctx.Err()
			}
		default:
			return false, fmt.Errorf("duo returned an unexpected result %q", st.Result)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

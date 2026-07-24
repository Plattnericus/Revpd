package duo

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

/* ------------------------------------------------------------- signing --- */

// Duo's reference client, for the worked example in their documentation.
var reference = &Client{
	apiHost: "api-XXXXXXXX.duosecurity.com",
	ikey:    "DIWJ8X6AEYOR5OMC6TQ1",
	skey:    "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep",
}

const referenceDate = "Tue, 21 Aug 2012 17:29:18 -0000"

func referenceParams() url.Values {
	p := url.Values{}
	p.Set("realname", "First Last")
	p.Set("username", "root")
	return p
}

// The canonical string is where signing goes wrong, so pin it byte for byte
// against the example Duo publishes.
func TestCanonicalStringMatchesDuosWorkedExample(t *testing.T) {
	got := reference.canonical(referenceDate, "POST", "/Accounts/v1/Account/List", referenceParams())

	want := strings.Join([]string{
		"Tue, 21 Aug 2012 17:29:18 -0000",
		"POST",
		"api-xxxxxxxx.duosecurity.com", // lowercased
		"/Accounts/v1/Account/List",
		"realname=First%20Last&username=root",
	}, "\n")

	if got != want {
		t.Fatalf("canonical string:\n got %q\nwant %q", got, want)
	}
}

// signature must be HMAC-SHA1 keyed with the secret over the canonical string,
// in that order. Swapping key and message is a classic mistake that still
// produces plausible-looking hex, so pin it against an RFC 2202 vector rather
// than against a value copied from documentation.
func TestSignatureIsHMACSHA1(t *testing.T) {
	c := &Client{skey: "Jefe"}

	const (
		message = "what do ya want for nothing?"
		want    = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" // RFC 2202, test case 2
	)

	if got := c.signature(message); got != want {
		t.Fatalf("signature = %q, want %q — the key and message may be swapped", got, want)
	}
}

// Different secrets must produce different signatures for the same request.
func TestSignatureDependsOnTheSecret(t *testing.T) {
	canon := reference.canonical(referenceDate, "POST", "/auth/v2/auth", referenceParams())

	a := (&Client{apiHost: reference.apiHost, skey: "secret-one"}).signature(canon)
	b := (&Client{apiHost: reference.apiHost, skey: "secret-two"}).signature(canon)

	if a == b {
		t.Fatal("the signature does not depend on the secret key")
	}
	if len(a) != 40 {
		t.Fatalf("signature is %d hex chars, want 40 for SHA-1", len(a))
	}
}

// Whatever date goes into the signature must be the one sent in the header.
// Signing one spelling and sending another is a silent 40103.
func TestSignedDateMatchesTheHeader(t *testing.T) {
	when := time.Date(2012, 8, 21, 17, 29, 18, 0, time.UTC)

	auth, date := reference.sign("POST", "/Accounts/v1/Account/List", referenceParams(), when)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatalf("decode authorization header: %v", err)
	}
	ikey, sig, ok := strings.Cut(string(raw), ":")
	if !ok {
		t.Fatalf("authorization header is not ikey:sig — %q", raw)
	}
	if ikey != reference.ikey {
		t.Fatalf("ikey = %q", ikey)
	}

	// Recompute using the date that was actually sent; it must agree.
	want := reference.signature(reference.canonical(date, "POST", "/Accounts/v1/Account/List", referenceParams()))
	if sig != want {
		t.Fatalf("the header was signed with a different date than it carries")
	}
}

// Parameters must be sorted and escaped the way Duo expects: spaces as %20,
// never as +.
func TestEncodeParams(t *testing.T) {
	params := url.Values{}
	params.Set("zebra", "last")
	params.Set("alpha", "first")
	params.Set("space", "a b")

	got := encodeParams(params)
	want := "alpha=first&space=a%20b&zebra=last"

	if got != want {
		t.Fatalf("encodeParams = %q, want %q", got, want)
	}
	if encodeParams(nil) != "" {
		t.Fatal("empty params should encode to an empty string")
	}
}

func TestBasicAuthEncoding(t *testing.T) {
	for _, tc := range []struct{ user, pass string }{
		{"a", "b"},
		{"ikey", "sig"},
		{"DIWJ8X6AEYOR5OMC6TQ1", "f01811cbbf9561623ab45b893096267fd46a5178"},
		{"", ""},
		{"abc", "de"},
	} {
		got := strings.TrimPrefix(basicAuth(tc.user, tc.pass), "Basic ")
		want := base64.StdEncoding.EncodeToString([]byte(tc.user + ":" + tc.pass))
		if got != want {
			t.Errorf("basicAuth(%q,%q) = %q, want %q", tc.user, tc.pass, got, want)
		}
	}
}

/* --------------------------------------------------------------- mock ----- */

// duoMock stands in for the real service.
type duoMock struct {
	srv *httptest.Server

	mu       sync.Mutex
	result   string // what auth_status eventually reports
	waits    int    // how many "waiting" replies before deciding
	polls    int
	gotAuth  string
	gotParam url.Values
}

func newMock(t *testing.T, result string, waits int) *duoMock {
	t.Helper()
	m := &duoMock{result: result, waits: waits}

	mux := http.NewServeMux()

	mux.HandleFunc("/auth/v2/check", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		fmt.Fprint(w, `{"stat":"OK","response":{"time":1357020061}}`)
	})

	mux.HandleFunc("/auth/v2/auth", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		r.ParseForm()

		m.mu.Lock()
		m.gotParam = r.PostForm
		m.mu.Unlock()

		if m.result == "nodevice" {
			fmt.Fprint(w, `{"stat":"OK","response":{"result":"deny","status_msg":"no device"}}`)
			return
		}
		fmt.Fprint(w, `{"stat":"OK","response":{"txid":"tx-123"}}`)
	})

	mux.HandleFunc("/auth/v2/auth_status", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)

		m.mu.Lock()
		m.polls++
		remaining := m.waits
		if m.waits > 0 {
			m.waits--
		}
		res := m.result
		m.mu.Unlock()

		if remaining > 0 {
			fmt.Fprint(w, `{"stat":"OK","response":{"result":"waiting","status":"pushed"}}`)
			return
		}
		fmt.Fprintf(w, `{"stat":"OK","response":{"result":%q,"status":"answered"}}`, res)
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *duoMock) record(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gotAuth = r.Header.Get("Authorization")
}

// client points a Client at the mock, over plain HTTP.
func (m *duoMock) client() *Client {
	host := strings.TrimPrefix(m.srv.URL, "http://")

	c := New(Options{APIHost: host, IKey: "IKEY", SKey: "SKEY", Timeout: 5 * time.Second})
	c.Poll = 10 * time.Millisecond

	// The mock speaks HTTP, so rewrite the scheme on the way out.
	c.http.Transport = rewriteToHTTP{}
	return c
}

type rewriteToHTTP struct{}

func (rewriteToHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(r)
}

func (m *duoMock) pollCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.polls
}

func (m *duoMock) authParams() url.Values {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gotParam
}

/* -------------------------------------------------------------- approve --- */

func TestApproveAllowed(t *testing.T) {
	m := newMock(t, "allow", 0)

	ok, err := m.client().Approve(context.Background(), "felix", "203.0.113.7", "Office PC")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !ok {
		t.Fatal("an approved push was reported as declined")
	}

	// The push must carry enough for the person to recognise the attempt.
	p := m.authParams()
	if p.Get("username") != "felix" {
		t.Errorf("username = %q", p.Get("username"))
	}
	if p.Get("factor") != "push" {
		t.Errorf("factor = %q, want push", p.Get("factor"))
	}
	if p.Get("async") != "1" {
		t.Errorf("async = %q, want 1 — a blocking call would hold the request", p.Get("async"))
	}
	if p.Get("ipaddr") != "203.0.113.7" {
		t.Errorf("ipaddr = %q", p.Get("ipaddr"))
	}
	if !strings.Contains(p.Get("pushinfo"), "203.0.113.7") {
		t.Errorf("pushinfo does not mention the source address: %q", p.Get("pushinfo"))
	}
}

func TestApproveDenied(t *testing.T) {
	m := newMock(t, "deny", 0)

	ok, err := m.client().Approve(context.Background(), "felix", "203.0.113.7", "Office PC")
	if ok {
		t.Fatal("a declined push was reported as approved")
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

// The person takes a moment to tap; the client must keep waiting.
func TestApproveWaitsForTheAnswer(t *testing.T) {
	m := newMock(t, "allow", 3)

	ok, err := m.client().Approve(context.Background(), "felix", "203.0.113.7", "Office PC")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !ok {
		t.Fatal("approval was not picked up after waiting")
	}
	if m.pollCount() < 4 {
		t.Fatalf("polled %d times, expected to wait through 3 pending replies", m.pollCount())
	}
}

// An unanswered push must release when the hold timeout expires, not hang.
func TestApproveHonoursTheDeadline(t *testing.T) {
	m := newMock(t, "allow", 1000) // never answers

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	ok, err := m.client().Approve(ctx, "felix", "203.0.113.7", "Office PC")

	if ok {
		t.Fatal("an unanswered push was reported as approved")
	}
	if err == nil {
		t.Fatal("expected an error when the deadline passes")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Approve overran its deadline by %v", elapsed)
	}
}

// An account with nothing to push to is a denial, not a crash.
func TestApproveWithNoDevice(t *testing.T) {
	m := newMock(t, "nodevice", 0)

	ok, err := m.client().Approve(context.Background(), "felix", "203.0.113.7", "")
	if ok {
		t.Fatal("approved despite there being no device")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestCheck(t *testing.T) {
	m := newMock(t, "allow", 0)

	if err := m.client().Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

/* --------------------------------------------------------- configuration --- */

// Missing configuration yields a nil client, which callers treat as
// "push unavailable" rather than crashing.
func TestNewReturnsNilWhenUnconfigured(t *testing.T) {
	cases := []Options{
		{},
		{APIHost: "api.duosecurity.com"},
		{APIHost: "api.duosecurity.com", IKey: "x"},
		{IKey: "x", SKey: "y"},
	}
	for i, o := range cases {
		if c := New(o); c != nil {
			t.Errorf("case %d: expected nil for incomplete configuration", i)
		}
	}

	full := New(Options{APIHost: "api.duosecurity.com", IKey: "x", SKey: "y"})
	if !full.Configured() {
		t.Fatal("a fully configured client reports itself as unconfigured")
	}
}

// A nil client must be safe to call, so callers need no nil checks.
func TestNilClientIsSafe(t *testing.T) {
	var c *Client

	if c.Configured() {
		t.Fatal("a nil client reported itself as configured")
	}
	if ok, err := c.Approve(context.Background(), "felix", "", ""); ok || !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Approve on a nil client returned %v, %v", ok, err)
	}
}

// The host may be given with or without a scheme.
func TestAPIHostIsNormalised(t *testing.T) {
	for _, in := range []string{"api-abc.duosecurity.com", "https://api-abc.duosecurity.com"} {
		c := New(Options{APIHost: in, IKey: "x", SKey: "y"})
		if c.apiHost != "api-abc.duosecurity.com" {
			t.Errorf("APIHost %q normalised to %q", in, c.apiHost)
		}
	}
}

// The secret key must never appear in an error returned to a caller.
func TestErrorsDoNotLeakTheSecret(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v2/auth", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"stat":"FAIL","code":40103,"message":"Invalid signature"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(Options{APIHost: strings.TrimPrefix(srv.URL, "http://"), IKey: "IKEY", SKey: "SUPERSECRETKEY", Timeout: 5 * time.Second})
	c.http.Transport = rewriteToHTTP{}

	_, err := c.Approve(context.Background(), "felix", "", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETKEY") {
		t.Fatalf("the error leaks the secret key: %v", err)
	}
}

package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLogs points the default logger at a buffer for the life of the test,
// so a test can read the one line it caused without racing every other
// goroutine's logging.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestAccessLogRecordsMethodPathStatusAndDuration(t *testing.T) {
	buf := captureLogs(t)
	s := &Server{}

	h := s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", nil)
	req.RemoteAddr = "203.0.113.9:51000"
	h.ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	for _, want := range []string{
		"method=POST", "path=/api/admin/targets", "status=201", "bytes=2", "src=203.0.113.9",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line does not contain %q: %s", want, line)
		}
	}
}

// A handler that never calls WriteHeader explicitly still gets 200, which is
// what net/http itself does — the log must not report a bare zero.
func TestAccessLogDefaultsToOKWhenWriteHeaderIsNeverCalled(t *testing.T) {
	buf := captureLogs(t)
	s := &Server{}

	h := s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/me", nil))

	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("log line does not say status=200: %s", buf.String())
	}
}

// The severity has to track the outcome, or a wall of identical INFO lines
// hides the one request that actually failed.
func TestAccessLogLevelTracksStatus(t *testing.T) {
	cases := []struct {
		status int
		level  string
	}{
		{http.StatusOK, "level=INFO"},
		{http.StatusNotFound, "level=WARN"},
		{http.StatusInternalServerError, "level=ERROR"},
	}

	for _, tc := range cases {
		buf := captureLogs(t)
		s := &Server{}

		h := s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

		if !strings.Contains(buf.String(), tc.level) {
			t.Errorf("status %d logged as %q, want %s", tc.status, buf.String(), tc.level)
		}
	}
}

// Whoever authed resolved has to reach the log line, without the log
// middleware knowing anything about sessions itself.
func TestAccessLogNamesTheAuthenticatedUser(t *testing.T) {
	buf := captureLogs(t)
	s := &Server{}

	h := s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noteRequestUser(r.Context(), "felix")
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/me", nil))

	if !strings.Contains(buf.String(), "user=felix") {
		t.Errorf("log line does not name the user: %s", buf.String())
	}
}

// A request nobody signed in for — the login endpoint itself, setup, static
// assets — must not crash the middleware or claim a user that was never
// resolved.
func TestAccessLogOmitsUserWhenNobodyIsSignedIn(t *testing.T) {
	buf := captureLogs(t)
	s := &Server{}

	h := s.withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/login", nil))

	if strings.Contains(buf.String(), "user=") {
		t.Errorf("an anonymous request was logged with a user: %s", buf.String())
	}
}

// fakeFlusher proves Flush reaches the real ResponseWriter through the
// wrapper — the live-status stream on /api/events depends on exactly this
// working, and a wrapper that only satisfies http.ResponseWriter would break
// it silently: the type assertion in the SSE handler would just fail.
type fakeFlusher struct {
	http.ResponseWriter
	flushed int
}

func (f *fakeFlusher) Flush() { f.flushed++ }

func TestStatusWriterForwardsFlush(t *testing.T) {
	ff := &fakeFlusher{ResponseWriter: httptest.NewRecorder()}
	sw := &statusWriter{ResponseWriter: ff}

	if _, ok := any(sw).(http.Flusher); !ok {
		t.Fatal("statusWriter does not implement http.Flusher at all")
	}
	sw.Flush()
	sw.Flush()

	if ff.flushed != 2 {
		t.Errorf("Flush reached the underlying writer %d times, want 2", ff.flushed)
	}
}

// The common case: the underlying writer is a plain httptest.ResponseRecorder
// that is not a Flusher. Flush must be a no-op, not a panic.
func TestStatusWriterFlushIsSafeWithoutAFlusher(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw.Flush() // must not panic
}

func TestStatusWriterIgnoresASecondWriteHeaderCall(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw.WriteHeader(http.StatusTeapot)
	sw.WriteHeader(http.StatusOK) // net/http itself would log "superfluous" here

	if sw.status != http.StatusTeapot {
		t.Errorf("status = %d, want the first call's 418 to stick", sw.status)
	}
}

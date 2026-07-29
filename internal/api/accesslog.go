package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

/*
	One structured line for every request the portal answers.

	Everything happens through this HTTP server — the dashboard, every admin
	action, the login itself — so a single access log here is what "complete"
	means for this gateway, the same way the audit trail is complete for
	security events. The two overlap on purpose rather than duplicating each
	other: the audit log says who did what and why it matters; this log says
	what the web server actually did with each request, which is the half an
	operator needs when something is slow, a client keeps retrying, or a
	request 404s and nobody can say why.

	Two rules keep it worth reading:

	Nothing from the request or response body ever reaches it. A password, a
	TOTP code, a session token or a CSRF header would otherwise be one grep
	away from a log file that outlives the reason anyone kept it. Method,
	path, status, size and timing are the whole payload.

	And it costs almost nothing: one small struct per request to carry the
	resolved username out of the handler chain, one wrapper around the
	response writer to see the status code Go does not otherwise expose. No
	buffering, no body copies, no reflection.
*/

// requestUser is filled in by authed/admin once a session resolves, so the
// access log can name who was signed in without repeating the session lookup
// itself. Anonymous for everything before that — the login endpoints, the
// setup wizard, static assets — which is a fact worth logging too, not an
// error.
type requestUser struct {
	name string
}

type accessLogCtxKey struct{}

func withRequestUser(ctx context.Context) (context.Context, *requestUser) {
	ru := &requestUser{}
	return context.WithValue(ctx, accessLogCtxKey{}, ru), ru
}

// noteRequestUser records who a request turned out to be, for the access log
// line that is still being assembled around it. A request with no box in its
// context — there is always one, but a test harness might call a handler
// directly — is silently a no-op rather than a panic.
func noteRequestUser(ctx context.Context, username string) {
	if ru, ok := ctx.Value(accessLogCtxKey{}).(*requestUser); ok {
		ru.name = username
	}
}

// withAccessLog is the outermost wrapper, so it sees every request that
// reaches this process and the true final status of every one of them.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ctx, ru := withRequestUser(r.Context())
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(sw, r.WithContext(ctx))

		fields := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.written,
			"duration_ms", time.Since(start).Milliseconds(),
			"src", s.clientIP(r).String(),
		}
		if ru.name != "" {
			fields = append(fields, "user", ru.name)
		}

		switch {
		case sw.status >= 500:
			slog.Error("http request", fields...)
		case sw.status >= 400:
			slog.Warn("http request", fields...)
		default:
			slog.Info("http request", fields...)
		}
	})
}

// statusWriter is the one thing net/http does not hand a handler: what status
// code actually went out. Flush is forwarded explicitly — the live-status
// stream on /api/events type-asserts for http.Flusher, and an
// http.ResponseWriter embedded as an interface does not promote it on its
// own, so leaving this out would silently break streaming the moment
// logging wrapped it.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Reason classifies why a check or download failed, so the dashboard can say
// something specific instead of surfacing a bare transport error.
type Reason string

const (
	ReasonNetwork     Reason = "network"     // never reached GitHub
	ReasonRateLimit   Reason = "rate_limit"  // too many anonymous requests from this address
	ReasonAuth        Reason = "auth"        // the configured token was refused
	ReasonNoRelease   Reason = "no_release"  // the repository has published nothing
	ReasonNotFound    Reason = "not_found"   // that specific tag does not exist
	ReasonNoAssets    Reason = "no_assets"   // a release with no files attached
	ReasonNoBuild     Reason = "no_build"    // files, but none for this OS/architecture
	ReasonServer      Reason = "server"      // GitHub is failing
	ReasonCorrupt     Reason = "corrupt"     // checksum or archive did not hold up
	ReasonUnorderable Reason = "unorderable" // running an untagged build
)

// Failure carries a message written for whoever is looking at the dashboard,
// not for a log grepper. Every one of them says what went wrong and what to do.
type Failure struct {
	Reason  Reason
	Message string

	// RetryAfter is set when waiting is the fix, as with a rate limit.
	RetryAfter time.Time

	Err error
}

func (f *Failure) Error() string { return f.Message }
func (f *Failure) Unwrap() error { return f.Err }

func failf(reason Reason, err error, format string, args ...any) *Failure {
	return &Failure{Reason: reason, Message: fmt.Sprintf(format, args...), Err: err}
}

// Asset is one file attached to a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is the subset of GitHub's release object this needs.
type Release struct {
	Tag         string    `json:"tag_name"`
	Name        string    `json:"name"`
	Notes       string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset returns the named file, or nil.
func (r *Release) Asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// AssetNames lists what the release actually carries, for error messages that
// tell the operator what they got instead of what they wanted.
func (r *Release) AssetNames() []string {
	out := make([]string, 0, len(r.Assets))
	for _, a := range r.Assets {
		out = append(out, a.Name)
	}
	return out
}

// Client talks to the GitHub releases API for one repository.
type Client struct {
	// Repo is "owner/name". Empty means DefaultRepo.
	Repo string

	// Token raises the anonymous rate limit and reaches private repositories.
	Token string

	HTTP *http.Client

	// base overrides the API root so tests can serve a repository locally.
	// Empty means api.github.com.
	base string
}

// DefaultRepo derives owner/name from the module path this binary was built
// from, so a fork updates from the fork without anyone editing a constant.
func DefaultRepo() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Path != "" {
		if p := strings.TrimPrefix(info.Main.Path, "github.com/"); p != info.Main.Path {
			if parts := strings.Split(p, "/"); len(parts) >= 2 {
				return parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}

func (c *Client) repo() string {
	if c.Repo != "" {
		return c.Repo
	}
	return DefaultRepo()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) token() string {
	if c.Token != "" {
		return c.Token
	}
	return os.Getenv("GITHUB_TOKEN")
}

// Latest returns the newest published, non-draft, non-pre-release.
//
// When includePrerelease is set the release list is used instead, because
// GitHub's own "latest" deliberately skips pre-releases.
func (c *Client) Latest(ctx context.Context, includePrerelease bool) (*Release, error) {
	if c.repo() == "" {
		return nil, failf(ReasonNotFound, nil,
			"no update repository is configured and none could be derived from this build — set update.repo in revpd.yaml")
	}

	if includePrerelease {
		list, err := c.list(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			if !r.Draft {
				rel := r
				return &rel, nil
			}
		}
		return nil, c.explainNoRelease(ctx, list)
	}

	var rel Release
	status, err := c.get(ctx, c.api("/releases/latest"), &rel)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		list, lerr := c.list(ctx)
		if lerr != nil {
			return nil, lerr
		}
		return nil, c.explainNoRelease(ctx, list)
	}
	if rel.Tag == "" {
		return nil, failf(ReasonServer, nil,
			"GitHub returned a release for %s with no tag on it — this should not happen", c.repo())
	}
	return &rel, nil
}

// ByTag fetches one specific release.
func (c *Client) ByTag(ctx context.Context, tag string) (*Release, error) {
	var rel Release
	status, err := c.get(ctx, c.api("/releases/tags/"+url.PathEscape(tag)), &rel)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, failf(ReasonNotFound, nil,
			"%s has no release tagged %q. The tag has to match exactly, including the leading v.",
			c.repo(), tag)
	}
	return &rel, nil
}

func (c *Client) list(ctx context.Context) ([]Release, error) {
	var list []Release
	status, err := c.get(ctx, c.api("/releases?per_page=100"), &list)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, failf(ReasonNotFound, nil,
			"the repository %s does not exist or is private. Check update.repo, or set a GITHUB_TOKEN that can read it.",
			c.repo())
	}
	return list, nil
}

// explainNoRelease turns "nothing to install" into the reason there is
// nothing: no releases at all, or only drafts and pre-releases.
func (c *Client) explainNoRelease(ctx context.Context, list []Release) error {
	if len(list) == 0 {
		return failf(ReasonNoRelease, nil,
			"%s has not published any release yet, so there is nothing to update to.", c.repo())
	}

	var tags []string
	for _, r := range list {
		kind := "pre-release"
		if r.Draft {
			kind = "draft"
		}
		tags = append(tags, r.Tag+" ("+kind+")")
		if len(tags) == 5 {
			break
		}
	}
	return failf(ReasonNoRelease, nil,
		"%s has releases, but none of them is final — GitHub's \"latest\" skips drafts and pre-releases. Found: %s. Turn on update.prerelease to accept these.",
		c.repo(), strings.Join(tags, ", "))
}

func (c *Client) api(path string) string {
	base := c.base
	if base == "" {
		base = "https://api.github.com/repos/"
	}
	return base + c.repo() + path
}

// get performs one API call. A 404 comes back as a status rather than an
// error, because what a missing thing means depends on what was asked for.
func (c *Client) get(ctx context.Context, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, failf(ReasonNetwork, err, "could not build a request for %s", endpoint)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "revpd")
	if tok := c.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, networkFailure(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, failf(ReasonNetwork, err,
			"the connection to GitHub dropped part-way through the reply")
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, failf(ReasonServer, err,
				"GitHub's reply could not be read as JSON — something between here and GitHub is rewriting responses")
		}
		return resp.StatusCode, nil

	case resp.StatusCode == http.StatusNotFound:
		return resp.StatusCode, nil

	case resp.StatusCode == http.StatusUnauthorized:
		return resp.StatusCode, failf(ReasonAuth, nil,
			"GitHub rejected the configured token (401) — it is expired, revoked or malformed")

	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return resp.StatusCode, rateLimitFailure(resp, c.token() != "")

	case resp.StatusCode >= 500:
		return resp.StatusCode, failf(ReasonServer, nil,
			"GitHub is failing (HTTP %d). Nothing is wrong on this machine; check githubstatus.com.",
			resp.StatusCode)

	default:
		return resp.StatusCode, failf(ReasonServer, nil,
			"unexpected reply from GitHub (HTTP %d)%s", resp.StatusCode, apiMessage(body))
	}
}

func rateLimitFailure(resp *http.Response, haveToken bool) error {
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining != "0" {
		return failf(ReasonAuth, nil,
			"GitHub refused the request (403). If this repository is private, configure a token that can read it.")
	}

	f := &Failure{Reason: ReasonRateLimit}
	if secs, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		f.RetryAfter = time.Unix(secs, 0)
	}

	f.Message = "GitHub's API rate limit for this address is used up. Anonymous requests are capped at 60 an hour and counted per IP, so a shared address runs out on its own."
	if !haveToken {
		f.Message += " Setting GITHUB_TOKEN in /etc/revpd/.env raises the cap."
	}
	if !f.RetryAfter.IsZero() {
		f.Message += " It resets at " + f.RetryAfter.Format("15:04 MST") + "."
	}
	return f
}

// networkFailure names the specific thing that went wrong, because "no such
// host" and "certificate expired" need very different fixes.
func networkFailure(err error) error {
	msg := err.Error()

	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "timeout"):
		return failf(ReasonNetwork, err,
			"the connection to GitHub timed out — the route is slow, or an outbound firewall is dropping it")
	case strings.Contains(msg, "no such host"):
		return failf(ReasonNetwork, err,
			"api.github.com could not be resolved — DNS on this machine is not answering")
	case strings.Contains(msg, "connection refused"):
		return failf(ReasonNetwork, err,
			"the connection to GitHub was refused — an outbound firewall or a required proxy would both look like this")
	case strings.Contains(msg, "certificate"):
		return failf(ReasonNetwork, err,
			"the TLS certificate was rejected — check the system clock, the ca-certificates package, and whether a proxy is intercepting TLS")
	default:
		return failf(ReasonNetwork, err, "could not reach GitHub: %v", err)
	}
}

func apiMessage(body []byte) string {
	var v struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &v) == nil && v.Message != "" {
		return ": " + v.Message
	}
	return ""
}

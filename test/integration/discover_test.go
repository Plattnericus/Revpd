//go:build integration

// Whether nmap is installed changes what discovery can tell an operator, and
// that fact has to reach the browser honestly rather than being guessed at
// from how confident a result looks.
package integration

import (
	"net/http"
	"testing"
)

func TestDiscoverRangesReportsWhetherNmapIsAvailable(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "GET", "/api/admin/discover/ranges", nil, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discover/ranges returned %d", resp.StatusCode)
	}

	body := decodeBody(t, resp)
	if _, ok := body["nmap_available"]; !ok {
		t.Fatal("the response does not say whether nmap is available at all")
	}
	// The field must be a real boolean, not a stand-in that would read as
	// truthy or falsy in ways JSON callers do not expect.
	if _, ok := body["nmap_available"].(bool); !ok {
		t.Errorf("nmap_available = %v (%T), want a bool", body["nmap_available"], body["nmap_available"])
	}
}

// Discovery reaches into the local network — only an administrator decides
// to do that, same as everything else under /api/admin.
func TestDiscoverRangesIsAdminOnly(t *testing.T) {
	e := newAPI(t)

	resp := e.call(t, "GET", "/api/admin/discover/ranges", nil, nil, "")
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an unauthenticated request could read the network's discovery ranges")
	}
}

//go:build integration

// The public address: what the portal tells people to connect to, and who is
// allowed to ask.
package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/plattnericus/revpd/internal/config"
	"github.com/plattnericus/revpd/internal/store"
)

/*
	The feature under test is "open one port on the router and reach this from
	anywhere". Three things have to hold for that to work:

	  - the address printed is the one the internet can reach, not the LAN one
	  - the port printed is the one forwarded, which need not be 3389
	  - none of it changes who may connect

	The last one is the important one. This is display data, and display data
	that could influence a forwarding decision would be a way in.
*/

func TestConnectAddressUsesThePublicHostAndPort(t *testing.T) {
	e := newAPIWith(t, func(c *config.Config) {
		c.Public.Host = "remote.example.org"
		c.Public.RDPPort = 33890 // the router forwards this to 3389
	})
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "GET", "/api/targets", nil, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("targets returned %d", resp.StatusCode)
	}

	// Not gw.test, and not :3389 — both would send somebody to an address
	// that does not answer from outside.
	if got := decodeBody(t, resp)["gateway"]; got != "remote.example.org:33890" {
		t.Fatalf("gateway = %v, want remote.example.org:33890", got)
	}
}

func TestConnectAddressOmitsTheAssumedPort(t *testing.T) {
	// 3389 is what Remote Desktop assumes, so printing it would be noise.
	e := newAPIWith(t, func(c *config.Config) { c.Public.Host = "remote.example.org" })
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "GET", "/api/targets", nil, cookies, csrf)
	if got := decodeBody(t, resp)["gateway"]; got != "remote.example.org" {
		t.Fatalf("gateway = %v, want a bare hostname", got)
	}
}

func TestNetworkViewReportsTheForwardedPorts(t *testing.T) {
	e := newAPIWith(t, func(c *config.Config) {
		c.Public.Host = "remote.example.org"
		c.Public.RDPPort = 33890
		c.Public.PortalPort = 8443
	})
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "GET", "/api/admin/network", nil, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("network returned %d", resp.StatusCode)
	}
	body := decodeBody(t, resp)

	rdp, _ := body["rdp"].(map[string]any)
	if rdp["address"] != "remote.example.org:33890" {
		t.Errorf("rdp address = %v", rdp["address"])
	}
	// The interface needs to know this differs from the local port, because
	// that is the case that needs a sentence of explanation.
	if rdp["forwarded"] != true {
		t.Errorf("rdp forwarded = %v, want true", rdp["forwarded"])
	}
	if rdp["listen"] != ":3389" {
		t.Errorf("rdp listen = %v, want the local socket", rdp["listen"])
	}

	portal, _ := body["portal"].(map[string]any)
	if portal["address"] != "remote.example.org:8443" {
		t.Errorf("portal address = %v", portal["address"])
	}
	if body["portal_url"] != "https://remote.example.org:8443" {
		t.Errorf("portal_url = %v", body["portal_url"])
	}

	if body["source"] != "configured" {
		t.Errorf("source = %v, want configured", body["source"])
	}
	if body["detecting"] != false {
		t.Errorf("detecting = %v, want false", body["detecting"])
	}
}

func TestNetworkViewFallsBackToTheHostname(t *testing.T) {
	// An installation that set web.hostname and never touched public.host is
	// already correct and should not have to say it twice.
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	body := decodeBody(t, e.call(t, "GET", "/api/admin/network", nil, cookies, csrf))
	if body["host"] != "gw.test" {
		t.Fatalf("host = %v, want the configured hostname", body["host"])
	}
}

func TestChangingThePublicHostTakesEffectWithoutARestart(t *testing.T) {
	// It is a printed address and nothing else. Making somebody restart —
	// dropping every open desktop session — to change one would be absurd.
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/config", map[string]any{
		"values": map[string]string{
			"public.host":     "remote.example.org",
			"public.rdp_port": "33890",
		},
	}, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save returned %d: %v", resp.StatusCode, decodeBody(t, resp))
	}
	if body := decodeBody(t, resp); body["runtime"] != nil {
		runtime, _ := body["runtime"].(map[string]any)
		if runtime["restart_needed"] == true {
			t.Error("a changed public address should not ask for a restart")
		}
		if runtime["gateway"] != "remote.example.org:33890" {
			t.Errorf("gateway = %v, want the new address straight away", runtime["gateway"])
		}
	}

	// And the same on the endpoint the rest of the app reads.
	body := decodeBody(t, e.call(t, "GET", "/api/targets", nil, cookies, csrf))
	if body["gateway"] != "remote.example.org:33890" {
		t.Fatalf("gateway = %v, want the saved address", body["gateway"])
	}

	// The service that runs the staleness check has to have heard about it
	// too, or it would keep comparing DNS against the old name.
	if got := e.public.Current().Host; got != "remote.example.org" {
		t.Errorf("the address service still has %q", got)
	}
}

func TestPublicHostIsValidatedOnSave(t *testing.T) {
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	// Each of these would produce a connect string Remote Desktop cannot use.
	for _, bad := range []string{"https://remote.example.org", "remote.example.org:3389", "not a host"} {
		resp := e.call(t, "POST", "/api/admin/config", map[string]any{
			"values": map[string]string{"public.host": bad},
		}, cookies, csrf)

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("saving %q returned %d, want 400", bad, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// A refused save changes nothing at all.
	body := decodeBody(t, e.call(t, "GET", "/api/admin/network", nil, cookies, csrf))
	if body["configured"] != nil && body["configured"] != "" {
		t.Errorf("a rejected host was stored anyway: %v", body["configured"])
	}
}

func TestResolversOverPlainHTTPAreRefused(t *testing.T) {
	// The answer decides the address the portal hands out. Over HTTP anyone on
	// the path chooses it, which turns a display value into a redirect.
	e := newAPI(t)
	cookies, csrf := e.signIn(t)

	resp := e.call(t, "POST", "/api/admin/config", map[string]any{
		"values": map[string]string{
			"public.detect":    "true",
			"public.resolvers": "http://api.example.com",
		},
	}, cookies, csrf)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

/* --------------------------------------------------------- who may ask --- */

func TestNetworkEndpointsAreAdminOnly(t *testing.T) {
	// Knowing the public address is knowing where to aim. It is not a secret
	// worth much, but the check that forces a fresh lookup reaches out to a
	// third party and opens connections, and that is not an ordinary user's
	// button to press.
	e := newAPI(t)

	resp := e.call(t, "POST", "/api/login", map[string]string{
		"username": "anna", "password": apiPassword,
	}, nil, "")
	cookies := resp.Cookies()
	resp.Body.Close()

	for _, c := range []struct {
		method, path string
	}{
		{"GET", "/api/admin/network"},
		{"POST", "/api/admin/network/check"},
	} {
		resp := e.call(t, c.method, c.path, nil, cookies, csrfOf(cookies))
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s %s answered a half-authenticated session", c.method, c.path)
		}
		resp.Body.Close()
	}

	// And with no session at all.
	for _, c := range []struct {
		method, path string
	}{
		{"GET", "/api/admin/network"},
		{"POST", "/api/admin/network/check"},
	} {
		resp := e.call(t, c.method, c.path, nil, nil, "")
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d to an anonymous caller", c.method, c.path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestNetworkCheckDoesNotProbeUnlessAsked(t *testing.T) {
	// Probing opens TCP connections. It should happen when somebody presses
	// the button and never as a side effect of loading a page.
	e := newAPIWith(t, func(c *config.Config) { c.Public.Host = "remote.example.org" })
	cookies, csrf := e.signIn(t)

	body := decodeBody(t, e.call(t, "POST", "/api/admin/network/check", nil, cookies, csrf))
	if body["reach"] != nil {
		t.Errorf("reach = %v, want nothing without probe:true", body["reach"])
	}

	body = decodeBody(t, e.call(t, "GET", "/api/admin/network", nil, cookies, csrf))
	if body["reach"] != nil {
		t.Errorf("a plain read should never probe: %v", body["reach"])
	}
}

func TestRDPFileCarriesThePublicAddress(t *testing.T) {
	e := newAPIWith(t, func(c *config.Config) {
		c.Public.Host = "remote.example.org"
		c.Public.RDPPort = 33890
	})
	cookies, csrf := e.signIn(t)

	ctx := t.Context()
	id, err := e.db.CreateTarget(ctx, store.Target{
		Name: "Office PC", IP: "192.168.1.40", RDPPort: 3389,
		MAC: "aa:bb:cc:dd:ee:ff", BootTimeoutS: 120,
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	felix, err := e.db.UserByName(ctx, "felix")
	if err != nil {
		t.Fatalf("look up felix: %v", err)
	}
	if err := e.db.GrantTargetAccess(ctx, felix.ID, id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	resp := e.call(t, "GET", fmt.Sprintf("/api/targets/%d/rdpfile", id), nil, cookies, csrf)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rdpfile returned %d", resp.StatusCode)
	}

	raw, _ := io.ReadAll(resp.Body)

	// The port is written out rather than assumed: the whole point of
	// forwarding a different one is that the assumption is wrong.
	if !strings.Contains(string(raw), "full address:s:remote.example.org:33890") {
		t.Fatalf("the .rdp file does not point at the public address:\n%s", raw)
	}
}

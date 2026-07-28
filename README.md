<div align="center">

# Revpd

**Reach your Windows PC over RDP from anywhere — safely.**

Your PC stays off until you need it. Port 3389 is never exposed unprotected.
You connect with the Remote Desktop client that is already on every Windows
machine — nothing to install on the client.

</div>

```
You (Remote Desktop)  →  Revpd  →  MFA  →  Wake-on-LAN  →  your PC
```

---

## What you can do with it

| | |
|---|---|
| **Connect from anywhere** | Type your password and one-time code into Remote Desktop. That is the whole login. |
| **Leave the PC switched off** | Revpd wakes it with Wake-on-LAN when you connect, and waits while it boots. |
| **Keep port 3389 safe** | No valid code, no connection. Not one byte reaches your PC without MFA. |
| **Use any second factor** | Authenticator app, Duo push, passkey, or a printed backup code. |
| **Manage it from a menu** | Type `revpd` and everything is a numbered choice. No flags to memorise. |
| **Move to new hardware** | One encrypted backup file holds everything. Copy it over, restore, done. |
| **See who did what** | A tamper-evident log. `revpd audit verify` proves nobody edited it. |
| **Hear about it** | A message on your phone when somebody connects or an account locks itself. |

Everything is one file: a static binary, about 18 MB, no runtime to install and
no database to set up.

---

## Install

Pick whichever fits. The first is right if you are not sure.

<details open>
<summary><b>Debian or Ubuntu — one line</b></summary>

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/install.sh | sudo bash
```

Downloads the right build, checks its signature, creates a locked-down system
account, generates your encryption key, installs a hardened service, and walks
you through your first login with a QR code.

Missing tools like `curl` or `tar` are installed for you. Run it again any time
to upgrade — your data, key and settings are never touched. After the first
install you can update from the web interface instead; see
[Staying current](#staying-current).

</details>

<details>
<summary><b>Docker — for Synology, unRAID, Proxmox, anything without systemd</b></summary>

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/deploy/revpd.example.yaml -o revpd.yaml
docker run --rm ghcr.io/plattnericus/revpd:latest genkey > .env

docker compose up -d
```

> `network_mode: host` is required, not a shortcut. Wake-on-LAN works at the
> network-card level, and from inside Docker's own network the wake-up signal
> would never reach your PC.

</details>

<details>
<summary><b>From source — needs Go 1.23+ and Node 20+</b></summary>

```bash
git clone https://github.com/plattnericus/revpd && cd revpd
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o revpd ./cmd/revpd
```

The web interface is compiled into the binary, so build it first.

Pass the version in if you want `revpd update` to be able to order this build
against published releases — without it the binary reports `dev`, and the
updater refuses to compare (and so to replace) a build somebody made by hand:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=1.2.3" -o revpd ./cmd/revpd
```

</details>

<details>
<summary><b>Publishing a release — for maintainers</b></summary>

Releasing is one step, and files never have to be attached by hand. Either:

- **Draw up a release in the web interface** and publish it, or
- **`git tag v1.2.3 && git push origin v1.2.3`**

[`.github/workflows/release.yml`](.github/workflows/release.yml) fires on both.
It builds the web interface, compiles for linux/amd64 and linux/arm64, packages
`revpd_<version>_linux_<arch>.tar.gz` plus `checksums.txt`, checks that the
archive unpacks to a binary reporting the expected version, and attaches
everything to the release.

For the couple of minutes between publishing and the build finishing, the
release exists with nothing attached. Nothing breaks in that window:

- `install.sh` notices a build is running and waits for it.
- The dashboard shows the new version and says its build is not ready yet,
  rather than offering a button that would fail.

And if no build is coming at all — a release published before this workflow
existed, or a fork without Actions — `install.sh` downloads the tag's source
archive, fetches verified Go and Node toolchains if the machine's own are
missing or too old, and compiles the release itself. Set `REVPD_NO_BUILD=1` to
refuse rather than compile.

To repair an old release, run the workflow from the Actions tab and give it the
existing tag.

</details>

---

## Set up

**1. Add the PC you want to reach**

```bash
sudo revpd target add "Office PC" 192.168.1.40 aa:bb:cc:dd:ee:ff --for felix
```

The MAC address is what wakes it. Any format works.

**2. Forward two ports on your router to this server**

| Port | For |
|---|---|
| `3389` | Remote Desktop |
| `8443` | web interface |

Nothing else. Your Windows PC itself stays completely closed —
[the firewall rules are here](deploy/HARDENING.md).

Revpd works out what address that makes it reachable at, and the settings page
shows what to type from outside. If you forwarded a *different* port — say
`33890` to `3389`, which keeps the internet's constant scan of 3389 off your
door — say so and every address it prints follows:

```yaml
public:
  rdp_port: 33890     # connect to gw.example.com:33890
```

Have a domain, or a dynamic-DNS name? Put it in `public.host` and it wins over
anything detected. Revpd keeps checking that it still points here, because a
DynDNS record that quietly stopped following your connection is the difference
between getting in from anywhere and finding out you cannot.

[More on all of this below.](#reaching-it-from-anywhere)

**3. On the Windows PC, turn off Fast Startup**

```powershell
powercfg /hibernate off
```

This is the single most common reason Wake-on-LAN appears not to work: with
Fast Startup on, shutting down leaves the network card unpowered.

---

## Connect

1. Open **Remote Desktop**
2. Computer: your gateway, e.g. `gw.example.com`
3. Username: as usual
4. **Password field: your password, a comma, then your code**

```
MyPassword,123456        code from your authenticator app
MyPassword,push          approve on your phone (needs Duo)
MyPassword,K7RM2-9XQPD   backup code
```

Revpd checks both, wakes your PC, waits for it, and connects you
automatically. **You type once.**

If the PC was off, the first attempt takes as long as it takes to boot.

> A comma in your password is fine — only the last one counts.

---

## Manage it

Type `revpd` for a menu, or use commands directly.

```
revpd                          open the menu
revpd status                   is it running, how many users and machines

revpd user add NAME --admin    create an account
revpd user list
revpd user rm NAME
revpd user reset NAME          new QR code and backup codes
revpd user lock NAME           lock someone out immediately

revpd target add NAME IP MAC --for USER
revpd target list
revpd target rm NAME

revpd service restart          start, stop, restart, status
revpd logs -f                  watch what it is doing

revpd backup                   everything in one encrypted file
revpd restore FILE

revpd audit verify             prove the log was not tampered with
revpd uninstall                remove it completely
```

### The web interface

`https://your-gateway:8443` — the first visit walks you through creating your
account and scanning a QR code. After that: machines, users, access, the
activity log, and a wake button as a fallback.

Ten languages, light and dark, works on a phone.

### Getting told about it

Settings → Notifications sends a short message when something happens that is
worth knowing about while you are away from the machine: somebody connected, an
account locked itself, an approval is waiting.

```
Remote desktop connected
felix → Büro-PC from 203.0.113.9
```

It goes to an [ntfy](https://ntfy.sh) topic, a Discord or Slack webhook, or any
URL that takes a JSON POST. The destination is a password in its own right —
whoever has it can post to that channel — so plain HTTP is only accepted to an
address on your own network, and it never appears in a log line.

Pick the events yourself; `relay.open`, `lockout` and `jit.requested` are the
default. A burst is rate-limited to five messages and then one every half
minute, with the number held back written into the next one — a gateway being
guessed at should wake you once, not forty times.

**Send a test** posts a real message, because a topic name with a typo in it
looks fine from here and is otherwise discovered by the alert that never came.

---

## Reaching it from anywhere

The plan is one port on the router and a desktop from anywhere, with a second
factor in front of it. The gateway's own sockets are no help in setting that
up: behind NAT they only ever see the LAN, so neither the address people type
nor the port the router forwards is visible from in here.

So Revpd works both out, and the settings page shows the result.

**The address.** If a public address is bound to one of this machine's own
interfaces — any VPS — that is the answer and nobody is asked. Otherwise the
question goes to three small endpoints that reply with the caller's address,
and **two of them have to agree** before the answer is used. One endpoint
having a bad day, or a bad owner, cannot move the result on its own. They are
`public.resolvers`, they must be HTTPS, and they can be anything that behaves
the same — including something you run yourself.

`public.detect: false` switches the whole thing off, and then this gateway
never mentions itself to anybody.

**Your own name instead.** Set `public.host` to a domain or a dynamic-DNS name
and it wins over detection. Detection keeps running beside it for one reason:
to notice when the name stops pointing here and say so, rather than letting you
discover it from the wrong side of the internet.

**The port.** `public.rdp_port` is what your router forwards to `relay.listen`.
Leave it at `0` when the two match. Set it and every printed address follows —
the connect string, the downloaded `.rdp` file, the CLI. `public.portal_port`
does the same for the web interface.

**Does it actually work?** *Test from outside* on the settings page knocks on
your own public address. If it answers, the whole path is proven: forward,
firewall, listener. If it does not, Revpd says *could not confirm* rather than
*broken* — most routers refuse to connect back to themselves from the inside,
so a failure here often means nothing at all. The real test is your phone on
mobile data.

> **None of this decides anything.** The public address is a display value:
> it feeds the connect string and the `.rdp` file, and no grant, token or
> forwarding decision ever reads it. That separation is deliberate — part of
> the answer comes from a stranger, and a stranger can lie. What actually lets
> a connection through is unchanged: a passed second factor, and nothing else.

All of it is editable from **Settings → From the internet**, and changing the
address or a port takes effect immediately — no restart, so nobody's open
desktop session is dropped to correct a printed address.

## Staying current

Revpd checks GitHub for a newer release every few hours and shows what it finds
on the overview page. Nothing is downloaded until somebody asks for it.

**From the web interface.** When a release is available a panel appears at the
top of the overview with the version and what changed. Press *Install now* and
it downloads the build for this machine, checks it against the checksums
published with the release, replaces the binary and restarts. If the new
version does not come back up, the previous one is put back automatically and
the panel says why.

**Automatically.** Settings → Update has a switch. With it on, new releases
install themselves, and by default they wait until nobody is connected — an
update means a restart, and a restart drops any open remote desktop session.
The starting value comes from `update.auto_install` in `revpd.yaml`; the switch
overrides it from then on.

**From the terminal.**

```bash
revpd update                  # is there a newer release?
sudo revpd update install     # download, verify, install, confirm it came back
sudo revpd update rollback    # go back to the version before the last update
```

Installing needs root, because the service itself runs unprivileged with `/usr`
mounted read-only and cannot replace its own binary. `install.sh` sets up a
small root-owned unit for exactly that hand-off, which is what makes the button
in the web interface work. Without it, downloads still happen and the interface
says so, but installing has to be done from the command line.

Configuration lives under `update:` in
[`deploy/revpd.example.yaml`](deploy/revpd.example.yaml).

---

## Backups

```bash
sudo revpd backup
```

One encrypted file with your database, your encryption key and your settings.
Move it to a new machine and restore:

```bash
scp revpd-gw-2026-07-24.revpd-backup user@new-server:
ssh user@new-server sudo revpd restore revpd-gw-2026-07-24.revpd-backup
```

Everyone's second factors keep working, because the key travels with it.

> The file is encrypted with a passphrase you choose. There is no way to
> recover that passphrase, and no way to read the backup without it.

---

## How it works

Remote Desktop has no box to type a one-time code into. So Revpd answers the
connection itself and uses two things the protocol already provides:

**Your login arrives readable.** By choosing TLS instead of NLA for the first
hop, your username and password arrive inside the encrypted tunnel where the
gateway can check them.

**Your client redirects itself.** Once your code checks out, Revpd replies with
a [Server Redirection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/df3d59e6-30a8-4a36-bd2d-9d11bcd96c3e)
— the same mechanism Windows server farms use for load balancing. Your client
reconnects on its own, carrying a token that works exactly once.

After that Revpd stops looking at the traffic entirely and just copies bytes.

> **That is why nothing is lost.** NLA, clipboard, multiple monitors, audio and
> drive redirection all keep working, encrypted end to end between your client
> and your actual PC.

**The one rule:** without a passed MFA check, not a single byte is forwarded.

---

## Security

| | |
|---|---|
| Passwords | Argon2id (64 MiB, t=3, p=4) |
| One-time codes | RFC 6238, and a used code is dead — even if two logins race |
| Passkeys | WebAuthn Level 2, phishing-resistant, clone detection |
| Duo | Auth API v2, HMAC-signed |
| Secrets at rest | AES-256-GCM, key only ever from the environment |
| Redirect tokens | single use, tied to your address, valid 60 seconds |
| Brute force | escalating lockout per account and per address, tarpit on 3389 |
| The log | hash-chained and append-only |
| The process | never runs as root |
| Error messages | wrong password, unknown account and wrong code are indistinguishable |

Your password never appears in a log, an error, or the audit trail — there is a
test that reads the entire trail to prove it.

```bash
revpd audit verify
```

Each entry carries the hash of the one before it. Change or delete a line and
this tells you exactly where.

Firewall rules, locking down the Windows side, fail2ban and backups:
**[deploy/HARDENING.md](deploy/HARDENING.md)**.

---

## Tests

```bash
go test ./...                                     # unit tests
go test ./test/integration -tags=integration -v   # 78 end-to-end tests
go test ./internal/proxy/x224 -fuzz=FuzzRead      # parsers against random input
```

The integration suite runs the real thing: a sleeping PC, a real password with
a real code appended, a verified wake-up signal on the wire, a real boot, and a
byte-exact RDP stream at the end.

It also tries to break in — replaying tokens, racing two logins with one code,
holding connections open, and probing whether the responses reveal which
accounts exist. Every parser that faces the internet before authentication runs
under fuzzing.

---

## Requirements on the Windows PC

- Wake-on-LAN enabled in BIOS/UEFI
- Network adapter: *Allow this device to wake the computer*
- **Fast Startup off** (`powercfg /hibernate off`)
- Leave NLA on

Wake-on-LAN works at the network-card level, so across subnets your router
needs to allow directed broadcast.

---

## Status

Ready to use: RDP login, transparent relay, Wake-on-LAN, authenticator apps,
Duo, passkeys, web interface, setup wizard, installer, backups and the
management menu.

The RD Gateway on 443 (for networks where 3389 cannot be opened at all) is half
finished — the protocol works and is tested, the transport layer is not written
yet.

---

## Licence

MIT

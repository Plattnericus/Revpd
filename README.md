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
to upgrade — your data, key and settings are never touched.

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

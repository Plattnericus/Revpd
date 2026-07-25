# Manual acceptance

The things no test harness can prove for you: that a machine really wakes from
being off, that `mstsc` really connects, and that a session is actually usable
once it is up.

Everything else is covered by `go test ./...` and
`go test ./test/integration -tags=integration`. This file is the rest.

Work down the list on real hardware. Each step says what to do and what you
should see.

---

## Before you start

You need:

- the gateway running, with a machine registered and shared with your account
- an authenticator app holding that account's second factor
- the target's Wake-on-LAN settings actually enabled — see step 1

Check the gateway agrees it is healthy:

```bash
sudo revpd doctor
```

Everything should be a tick except the certificate, which stays self-signed
until you point `web.tls_cert` at a real one.

---

## 1. The target is ready to be woken

On the Windows machine, as administrator:

```powershell
powercfg /devicequery wake_armed
Get-NetAdapterAdvancedProperty -Name Ethernet | Where-Object DisplayName -match 'Wake|Magic'
```

The network adapter must appear in the first list, and both *Wake on Magic
Packet* and *Shutdown Wake-On-Lan* must be enabled.

**Fast Startup has to be off.** With it on, "shut down" is really a partial
hibernate and most adapters will not wake from it:

```powershell
powercfg /hibernate off
```

Confirm with `powercfg /a` that S3 is available and Fast Startup is gone.

---

## 2. The magic packet arrives

Leave the machine on for this one. On the Windows target, listen on the
Wake-on-LAN port — this needs a firewall rule for inbound UDP/9, or run it
elevated:

```powershell
# any small UDP listener will do; the point is to see the 102 bytes
```

Then, on the gateway:

```bash
sudo revpd wake "Office PC"
```

You should see 102 bytes arrive: six `0xFF` bytes followed by the target's MAC
address repeated sixteen times, sent three times over.

> Not seeing it in the OS does not mean Wake-on-LAN is broken. The adapter
> handles magic packets in firmware while the machine is off, below the
> firewall. This step only tells you the packet reaches the machine.

---

## 3. Waking from sleep, and from off

The one that matters. Do it twice.

**From S3 (sleep):** suspend the target, wait a minute, then:

```bash
sudo revpd wake "Office PC" --wait
```

It should report the machine up within a few seconds.

**From S5 (shut down):** shut the target down properly, wait a minute, and run
the same command. This is the one Fast Startup breaks, so if S3 works and S5
does not, go back to step 1.

---

## 4. Connecting the normal way

From a machine that has never talked to the gateway, open Remote Desktop and
connect to the gateway itself — not the target:

```
Computer:  gw.example.com
Username:  your gateway account
Password:  YourPassword,123456
```

The code from your authenticator goes after the last comma. What should happen:

1. a certificate warning, once — it is self-signed
2. a pause while the machine wakes
3. the connection reappears and Windows signs you in

You typed one thing and ended up on the desktop. If Windows asks for the
password again, the gateway account's password and the Windows account's
password differ — the redirection hands the former to the latter.

Wrong code, right password: the connection should end without a redirection.

---

## 5. The session is a real session

Once you are on the desktop, confirm the parts a naive proxy would break:

- copy text in both directions, then copy a file
- if you use several screens, check the session spans them
- play a sound
- open a redirected drive from **This PC**
- leave it running for a few minutes under load, then check for stalls

All of this is end-to-end between `mstsc` and Windows. If any of it is broken,
the relay is interfering with the stream and that is a bug.

---

## 6. Reconnecting after the network drops

With a session open, disconnect the client's network for twenty seconds, then
put it back. `mstsc` reconnects on its own and **must not ask for a code
again** — that is what `grant.reuse_window` is for.

Beyond that window, a fresh connection should require the second factor again.

---

## 7. What must not work

Each of these should fail, and each should leave a line in `revpd audit`:

| Try this | Expected |
|---|---|
| Connect from an address that holds no grant | refused, nothing reaches the target |
| Wait out `grant.ttl`, then connect | refused |
| Connect from a second machine using the first one's grant | refused |
| Sign in with the right password and a wrong code | no redirection |
| Five wrong passwords in a row | locked out, right password refused too |

Then confirm the trail is intact:

```bash
sudo revpd audit verify
```

---

## 8. It survives a restart

```bash
sudo systemctl restart revpd
sudo revpd doctor
```

Accounts, machines and the audit chain all still there. A live session drops,
which is expected.

---

## 9. You can get it back

The test people skip and regret:

```bash
sudo revpd backup /somewhere/safe.revpd-backup
```

Then, on a spare machine or after `revpd uninstall --yes`, install again and:

```bash
sudo revpd restore /somewhere/safe.revpd-backup
```

Accounts, machines, second factors and the audit chain come back, and
`revpd audit verify` still passes. If you cannot do this, you do not have a
backup — you have a file.

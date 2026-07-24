# Hardening

How to run Revpd so that **port 3389 is open on exactly one machine** — the
gateway — and the Windows hosts stay unreachable from anywhere else.

Ordered by how much they actually protect you. The first three are the ones
that matter; the rest is depth.

---

## 1. The target must refuse everyone except the gateway

This is the single most important step. Without it, someone who finds a way
around the gateway still reaches Windows directly.

**On the router:** forward TCP 3389 to the Linux gateway only. Never to a
Windows host.

**On the Windows target**, restrict the built-in Remote Desktop rule to the
gateway's address. Run as administrator:

```powershell
Set-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP `
    -RemoteAddress 192.168.1.10 -Enabled True
Set-NetFirewallRule -Name RemoteDesktop-UserMode-In-UDP `
    -RemoteAddress 192.168.1.10 -Enabled True
```

Replace `192.168.1.10` with your gateway. Verify from another machine on the
LAN — the connection must be refused:

```powershell
Test-NetConnection 192.168.1.40 -Port 3389
```

**Keep NLA on.** Revpd never terminates the session's encryption, so NLA runs
end to end between the client and Windows. Leave it exactly as it is:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1
```

---

## 2. Firewall on the gateway

`nftables` (Debian 11+, Ubuntu 22.04+ default). Adjust the addresses and drop
this in `/etc/nftables.conf`:

```nft
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    set rdp_bruteforce {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }

    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # ICMP, so path MTU discovery keeps working.
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # SSH — restrict to your admin network, do not leave this open.
        ip saddr 192.168.1.0/24 tcp dport 22 accept

        # Web portal.
        tcp dport 8443 accept

        # ACME, only while renewing a certificate.
        tcp dport 80 accept

        # RDP. More than ten new connections a minute from one address is a
        # scanner, not a person: park it for an hour.
        tcp dport 3389 ct state new \
            add @rdp_bruteforce { ip saddr limit rate over 10/minute } \
            drop
        tcp dport 3389 accept
    }

    chain forward {
        type filter hook forward hook priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

```bash
sudo nft -c -f /etc/nftables.conf   # check before applying
sudo systemctl enable --now nftables
```

> The `forward` chain is `drop` on purpose. Revpd proxies at the application
> layer and never routes packets, so the gateway must not forward anything.

**With `ufw` instead:**

```bash
sudo ufw default deny incoming
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw allow 8443/tcp
sudo ufw limit 3389/tcp          # limit, not allow — this rate-limits
sudo ufw enable
```

---

## 3. Wake-on-LAN actually working

More installations fail here than on anything else.

**In the BIOS/UEFI:** enable *Wake on LAN* / *Power on by PCI-E*.

**In Windows**, on the network adapter:

```powershell
Get-NetAdapter | Enable-NetAdapterPowerManagement -WakeOnMagicPacket
```

Or through the GUI: Device Manager → adapter → Power Management → tick both
*Allow this device to wake the computer* and *Only allow a magic packet*.

**Turn off Fast Startup.** This is the usual culprit when Wake-on-LAN seems
broken: with it on, shutting down leaves the NIC unpowered and no magic packet
can reach it.

```powershell
powercfg /hibernate off
```

Or: Control Panel → Power Options → *Choose what the power buttons do* →
untick *Turn on fast startup*.

**Across subnets**, the magic packet needs directed broadcast on the router,
and `wol_broadcast` in the target must be the subnet's broadcast address
(`192.168.1.255`), not `255.255.255.255`.

Check it without leaving the gateway:

```bash
revpd targetadd -name test -ip 192.168.1.40 -mac aa:bb:cc:dd:ee:ff
# then press "Test MAC" in the web interface and watch the machine come up
```

---

## 4. A certificate for the RDP listener

Without one, Revpd generates a self-signed certificate and the Remote Desktop
client shows *the identity of the remote computer cannot be verified* — the
same prompt a stock Windows host produces. It is not dangerous, but it trains
people to click through warnings, which is its own problem.

To make it go away, point the RDP listener at a real certificate:

```yaml
rdp_login:
  tls_cert: /etc/revpd/tls/fullchain.pem
  tls_key: /etc/revpd/tls/privkey.pem
```

Let the `revpd` account read it:

```bash
sudo setfacl -m u:revpd:r /etc/letsencrypt/live/gw.example.com/privkey.pem
```

Alternatively, distribute the generated certificate
(`/var/lib/revpd/rdp-cert.pem`) to your clients' *Trusted Root* store via
Group Policy. That works well in an enterprise and needs no public DNS.

---

## 5. Fail2ban

The relay already tarpits and rate-limits, but banning at the packet level
costs less than answering.

`/etc/fail2ban/filter.d/revpd.conf`:

```ini
[Definition]
failregex = ^.*relay\.rejected.*"src_ip":"<HOST>".*$
            ^.*login\.fail.*src_ip=<HOST>.*$
ignoreregex =
```

`/etc/fail2ban/jail.d/revpd.conf`:

```ini
[revpd]
enabled  = true
port     = 3389,8443
filter   = revpd
backend  = systemd
journalmatch = _SYSTEMD_UNIT=revpd.service
maxretry = 8
findtime = 10m
bantime  = 2h
```

---

## 6. Restrict who may even reach the port

If your users connect from predictable places, an allowlist beats every other
control here. Country-level blocking with nftables and an ipset from a GeoIP
feed is a reasonable middle ground when you cannot pin exact addresses.

For a single-user homelab, consider not exposing 3389 at all: put WireGuard in
front and let Revpd handle MFA and Wake-on-LAN inside the tunnel. You lose the
"works from any Windows machine with no client software" property, which is
the whole point for some people and irrelevant for others.

---

## 7. Backups

One file matters, and one secret.

```bash
sudo systemctl stop revpd
sudo sqlite3 /var/lib/revpd/revpd.db ".backup '/root/revpd-$(date +%F).db'"
sudo systemctl start revpd
```

Back up `/etc/revpd/.env` **separately and offline**. It holds the key that
decrypts every enrolled second factor. Lose it and everyone re-enrols; leak it
together with the database and the second factor is worth nothing.

Check the audit trail has not been touched:

```bash
sudo -u revpd revpd audit verify -c /etc/revpd/revpd.yaml
```

---

## 8. Keep it current

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/install.sh | sudo bash
```

Re-running the installer upgrades the binary and restarts the service. It
never touches the database, the master key or your configuration.

Unattended security updates are worth having on a host that faces the
internet:

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## What Revpd does not protect you from

Worth being explicit about.

- **A compromised target.** Once you are through, you are on that machine. The
  gateway controls who gets in, not what they do afterwards.
- **A stolen password *and* a stolen second factor.** MFA raises the cost; it
  does not make an account unbreakable. Watch the audit log.
- **The gateway itself.** In pass-through mode it sees the Windows password
  during login, inside TLS. It is never stored or logged, but a root-level
  compromise of the gateway is a compromise of everything behind it. Turn off
  `pass_through_credentials` if that trade is not one you want; Windows will
  then ask for credentials again over NLA and the gateway never holds them.

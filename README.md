<div align="center">

# Revpd

**MFA-Gateway für RDP mit Wake-on-LAN**

Erreiche deinen Windows-PC von überall — mit der normalen
Windows-Remotedesktopverbindung, ohne Zusatzsoftware auf dem Client, ohne dass
der Rechner durchläuft, und ohne Port 3389 ungeschützt im Internet.

[Installation](#installation) · [Verbinden](#verbinden) · [Wie es funktioniert](#wie-es-funktioniert) ·
[Konfiguration](#konfiguration) · [Sicherheit](#sicherheit) · [Härtung](deploy/HARDENING.md)

</div>

```
Du (mstsc)  ──►  Revpd  ──►  MFA  ──►  Wake-on-LAN  ──►  dein PC
```

Ein statisches Binary, rund 18 MB. Keine Laufzeitumgebung, keine Datenbank
aufsetzen, keine Abhängigkeiten. Läuft ab etwa 30 MB Arbeitsspeicher.

---

## Installation

Drei Wege. Der erste ist der richtige, wenn du nicht sicher bist.

### 1. Einzeiler auf Debian oder Ubuntu

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/install.sh | sudo bash
```

Lädt die passende Version, **prüft die SHA-256-Summe**, legt einen
System-Benutzer ohne Login an, erzeugt den Schlüssel, installiert einen
gehärteten systemd-Dienst und führt dich durch den ersten Administrator samt
QR-Code.

Fehlende Werkzeuge wie `curl`, `tar` oder `coreutils` zieht es selbst nach —
auf Debian, Ubuntu, Fedora, RHEL, Arch und Alpine. Erneutes Ausführen
aktualisiert nur das Binary; Datenbank, Schlüssel und Konfiguration bleiben
unangetastet.

<details>
<summary>Unbeaufsichtigt oder mit fester Version</summary>

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/install.sh \
  | sudo REVPD_NONINTERACTIVE=1 REVPD_HOSTNAME=gw.example.com bash
```

`REVPD_VERSION=v1.0.0` fixiert eine Version statt der neuesten.
</details>

### 2. Docker

Für alles ohne systemd — Synology, unRAID, Proxmox-Container, macOS zum
Ausprobieren.

```bash
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/deploy/revpd.example.yaml -o revpd.yaml
docker run --rm ghcr.io/plattnericus/revpd:latest genkey > .env

docker compose up -d
```

Oder in einem Aufruf, ohne Compose:

```bash
docker run -d --name revpd \
  --network host \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  -v revpd-data:/var/lib/revpd \
  -v $PWD/revpd.yaml:/etc/revpd/revpd.yaml:ro \
  --env-file .env \
  --restart unless-stopped \
  ghcr.io/plattnericus/revpd:latest
```

> `--network host` ist kein Komfort, sondern nötig: Wake-on-LAN arbeitet auf
> Layer 2, und aus Dockers Bridge käme das Magic Packet nie ins Netz.

Das Image basiert auf *distroless* — keine Shell, kein Paketmanager, läuft als
unprivilegierter Benutzer.

### 3. Aus dem Quelltext

Braucht Go 1.23+ und Node 20+.

```bash
git clone https://github.com/plattnericus/revpd && cd revpd
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o revpd ./cmd/revpd
```

Das Frontend wird über `embed.FS` ins Binary gelinkt — deshalb muss
`npm run build` vor `go build` laufen.

---

## Nach der Installation

Zielrechner eintragen — im Webinterface oder auf der Kommandozeile:

```bash
sudo revpd targetadd -name "Büro-PC" -ip 192.168.1.40 \
                     -mac a8:a1:59:3c:d2:11 -for felix
```

Dann auf dem Router **genau zwei Ports** auf den Linux-Server weiterleiten:

| Port | Wofür |
|---|---|
| `3389` | Remotedesktopverbindung |
| `8443` | Webinterface |

Mehr nicht. Der Windows-PC selbst bleibt komplett dicht — die Regeln dafür
stehen in [deploy/HARDENING.md](deploy/HARDENING.md).

> Das Webinterface spricht **immer TLS**. Ohne konfiguriertes Zertifikat wird
> beim Start ein selbstsigniertes erzeugt, statt auf HTTP zurückzufallen — ein
> Sitzungs-Cookie darf nie im Klartext über die Leitung, und Passkeys
> funktionieren ohnehin nur im Secure Context.
>
> Wer auch 8443 nicht öffnen will, bindet es auf `127.0.0.1` und greift per
> `ssh -L 8443:127.0.0.1:8443` darauf zu. Dann bleibt nur ein einziger Port.

---

## Verbinden

1. Windows-Remotedesktopverbindung öffnen
2. Als Computer die Adresse des Gateways eintragen, z. B. `gw.example.com`
3. Benutzername wie gewohnt
4. **Ins Passwortfeld: Passwort, Komma, Code**

```
MeinPasswort,123456        Einmalcode aus der Authenticator-App
MeinPasswort,push          Freigabe per Push aufs Handy (Duo)
MeinPasswort,K7RM2-9XQPD   Backup-Code
```

Revpd prüft beides, weckt den Rechner und leitet dich automatisch weiter. Du
tippst genau einmal. Läuft der Rechner noch nicht, dauert der erste Versuch so
lange wie der Bootvorgang.

Ein Komma im Passwort ist kein Problem — getrennt wird am **letzten**.

---

## Wie es funktioniert

RDP kennt keinen eigenen Dialog für Einmalcodes. Revpd nimmt die Verbindung
deshalb selbst an und nutzt zwei Mechanismen, die im Protokoll vorgesehen sind:

**1. Die Anmeldedaten kommen lesbar an.** Verhandelt das Gateway
`PROTOCOL_SSL` statt `HYBRID`, läuft die Verbindung über TLS ohne NLA. Der
Client schickt Benutzername und Passwort dann im Client Info PDU — innerhalb
des TLS-Tunnels.

**2. Die Weiterleitung macht der Client selbst.** Nach bestandener MFA
antwortet Revpd mit einem [Server Redirection PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/df3d59e6-30a8-4a36-bd2d-9d11bcd96c3e).
`mstsc` verbindet sich daraufhin von allein neu und trägt ein Einmal-Token mit.
Derselbe Mechanismus trägt sonst die Lastverteilung in Windows-Farmen.

Ab der Weiterleitung fasst Revpd den Datenstrom **nicht mehr an**. Es kopiert
nur Bytes.

> **Deshalb bleiben NLA, Zwischenablage, Multi-Monitor, Audio und
> Laufwerks-Umleitung vollständig erhalten.** Die Verschlüsselung der Sitzung
> läuft Ende-zu-Ende zwischen deinem Client und dem echten Windows-Rechner.

**Die eine Regel:** Ohne bestandene MFA wird kein einziges Byte weitergeleitet.

---

## Konfiguration

Zwei Dateien.

| Datei | Inhalt |
|---|---|
| `/etc/revpd/revpd.yaml` | Verhalten: Ports, Zeiten, Limits |
| `/etc/revpd/.env` | Geheimnisse: Master-Key, Duo-Zugangsdaten |

Die Umgebung sticht die Datei. Alles steht kommentiert in
[`.env.example`](.env.example) und
[`deploy/revpd.example.yaml`](deploy/revpd.example.yaml).

```yaml
web:
  hostname: gw.example.com     # was Nutzer eintippen; zugleich die Passkey-Kennung
  tls_cert: /etc/revpd/tls/fullchain.pem
  tls_key:  /etc/revpd/tls/privkey.pem

rdp_login:
  enabled: true                # Anmeldung direkt in der Remotedesktopverbindung

grant:
  ttl: 2m                      # wie lange eine bestandene MFA zum Verbinden reicht
  reuse_window: 10m            # Reconnect nach Netzabbruch ohne neue MFA
```

Ein Tippfehler in einem Schlüssel lässt den Start fehlschlagen, statt still
ignoriert zu werden — bei Sicherheitseinstellungen ist das Absicht.

### Kommandos

```bash
revpd useradd -u felix -admin        # Konto anlegen
revpd enroll  -u felix               # QR-Code und Backup-Codes
revpd targetadd -name … -ip … -mac … # Zielrechner
revpd audit verify                   # Protokoll auf Manipulation prüfen
journalctl -u revpd -f               # Logs
```

---

## Webinterface

Erreichbar unter `https://<hostname>:8443`. Beim ersten Aufruf führt ein
Assistent in vier Schritten durch Administrator, zweiten Faktor mit QR-Code,
ersten Zielrechner und Abschluss.

Danach: Zielrechner, Benutzer, Freigaben, Protokoll und ein Wecken-Knopf als
Notfallweg. In zehn Sprachen, hell und dunkel, auch auf dem Handy.

---

## Sicherheit

| Bereich | Umsetzung |
|---|---|
| Passwörter | Argon2id, 64 MiB, t=3, p=4 |
| TOTP | RFC 6238 mit **Replay-Schutz** — ein benutzter Code ist verbraucht |
| Passkeys | WebAuthn Level 2, ES256 und RS256, Klon-Erkennung über den Zähler |
| Duo | Auth API v2, HMAC-SHA1-signiert, asynchrones Push |
| Backup-Codes | einmalig, Argon2id-gehasht |
| Geheimnisse | AES-256-GCM, Schlüssel nur aus der Umgebung |
| Weiterleitungs-Token | einmalig einlösbar, an die Quell-IP gebunden, 60 s gültig |
| Freigaben | IP-gebunden, kurzlebig, jederzeit widerrufbar |
| Brute Force | progressive Sperre je Konto und je IP, Tarpit auf 3389 |
| Protokoll | hash-verkettet und nur anfügbar |
| Prozess | läuft nicht als root, `CAP_NET_BIND_SERVICE` statt Vollzugriff |
| Fehlermeldungen | falsches Passwort, unbekanntes Konto und falscher Code sind von außen nicht unterscheidbar |

Passwörter erscheinen **nie** in Logs, Fehlermeldungen oder im Protokoll — ein
Test prüft das gegen den kompletten Audit-Trail.

```bash
revpd audit verify
```

Jeder Eintrag enthält den Hash seines Vorgängers. Wird eine Zeile geändert oder
gelöscht, nennt der Befehl die betroffene Stelle.

Firewall-Regeln, Windows-seitige Einschränkung, fail2ban und Backups stehen in
**[deploy/HARDENING.md](deploy/HARDENING.md)**.

---

## Tests

```bash
go test ./... -cover                              # Unit-Tests
go test ./test/integration -tags=integration -v   # komplette Kette
go test ./internal/proxy/x224 -fuzz=FuzzRead      # Parser gegen Zufallseingaben
cd web && npm run test:i18n                       # Übersetzungen vollständig
```

Der Integrationstest fährt den echten Ablauf durch: schlafender Rechner,
Passwort mit angehängtem Code, verifiziertes Magic Packet auf dem Draht,
Bootvorgang, byte-genauer RDP-Strom. Er prüft außerdem, dass ohne Freigabe, mit
abgelaufener Freigabe, von fremder IP, bei gesperrtem Konto, mit
wiederverwendetem Code und nach entzogener Berechtigung wirklich **null Bytes**
durchkommen.

Die Parser sehen die offene Welt vor jeder Authentifizierung und laufen deshalb
unter `go-fuzz`.

---

## Voraussetzungen am Zielrechner

- WoL im BIOS/UEFI aktivieren
- Netzwerkadapter: *Gerät kann den Computer aus dem Ruhezustand aktivieren*
- **Windows-Schnellstart deaktivieren** (`powercfg /hibernate off`) — mit
  Abstand die häufigste Ursache, wenn WoL scheinbar nicht funktioniert
- NLA eingeschaltet lassen

Wake-on-LAN arbeitet auf Layer 2. Über Subnetzgrenzen muss der Router Directed
Broadcast erlauben.

---

## Stand

Einsatzbereit: RDP-nativer Login, transparenter Relay, Wake-on-LAN, TOTP, Duo,
Passkeys, Webinterface, Setup-Assistent, Installer und Härtungsleitfaden.

Das RD-Gateway auf 443 (für Netze, in denen 3389 gar nicht nach außen darf) ist
zur Hälfte fertig: der Protokollkern steht und ist getestet, die
Transportschicht fehlt noch.

---

## Lizenz

MIT

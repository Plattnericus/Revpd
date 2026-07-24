#!/usr/bin/env bash
#
# Revpd installer.
#
#   curl -fsSL https://raw.githubusercontent.com/plattnericus/revpd/main/install.sh | sudo bash
#
# Safe to run again: it upgrades in place and never touches an existing
# database, master key or configuration.
#
# Environment overrides, useful for unattended installs:
#   REVPD_VERSION=v1.2.3     pin a release instead of taking the latest
#   REVPD_HOSTNAME=gw.example.com
#   REVPD_NONINTERACTIVE=1   skip every prompt, use defaults

set -Eeuo pipefail

REPO="plattnericus/revpd"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/revpd"
DATA_DIR="/var/lib/revpd"
SERVICE="/etc/systemd/system/revpd.service"
USER_NAME="revpd"

# --------------------------------------------------------------- output ----

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; BLUE=$'\033[34m'
else
    B=""; DIM=""; R=""; GREEN=""; YELLOW=""; RED=""; BLUE=""
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s%s%s\n' "$BLUE" "$R" "$B" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$R" "$*"; }
die()  { printf '\n%serror:%s %s\n' "$RED" "$R" "$*" >&2; exit 1; }

on_error() {
    local line=$1
    printf '\n%sinstall failed on line %s.%s\n' "$RED" "$line" "$R" >&2
    say "Nothing was left half-configured that a re-run will not fix." >&2
    say "Report it at https://github.com/${REPO}/issues" >&2
}
trap 'on_error $LINENO' ERR

# ---------------------------------------------------------------- checks ---

[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL … | sudo bash"

[ "$(uname -s)" = "Linux" ] || die "Revpd runs on Linux. For macOS or Windows, use Docker:
  https://github.com/${REPO}#docker"

# Package manager, so missing tools can be fetched rather than just reported.
if command -v apt-get >/dev/null 2>&1; then
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
elif command -v dnf >/dev/null 2>&1; then
    PKG_UPDATE="true"
    PKG_INSTALL="dnf install -y -q"
elif command -v yum >/dev/null 2>&1; then
    PKG_UPDATE="true"
    PKG_INSTALL="yum install -y -q"
elif command -v pacman >/dev/null 2>&1; then
    PKG_UPDATE="pacman -Sy --noconfirm"
    PKG_INSTALL="pacman -S --noconfirm --needed"
elif command -v apk >/dev/null 2>&1; then
    PKG_UPDATE="apk update -q"
    PKG_INSTALL="apk add -q"
else
    PKG_UPDATE=""
    PKG_INSTALL=""
fi

# ensure installs a command if it is missing, rather than stopping at the
# first thing a minimal image happens not to ship.
ensure() {
    local cmd=$1 pkg=${2:-$1}

    command -v "$cmd" >/dev/null 2>&1 && return 0

    if [ -z "$PKG_INSTALL" ]; then
        die "$cmd is required and no supported package manager was found.
Install it and run this again, or use Docker: https://github.com/${REPO}#docker"
    fi

    warn "$cmd is missing, installing it"
    if [ -n "$PKG_UPDATE" ] && [ -z "${_pkg_updated:-}" ]; then
        $PKG_UPDATE >/dev/null 2>&1 || true
        _pkg_updated=1
    fi
    $PKG_INSTALL "$pkg" >/dev/null 2>&1 \
        || die "could not install $cmd. Install it manually and run this again."

    command -v "$cmd" >/dev/null 2>&1 || die "$pkg installed but $cmd is still not on PATH"
}

ensure curl
ensure tar
ensure sha256sum coreutils

# systemd is how the service is supervised. Without it the binary still works,
# but this installer has nothing to hand it to.
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    die "systemd was not found (containers and WSL often lack it).
Use Docker instead: https://github.com/${REPO}#docker"
fi

case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m). Build from source instead:
  https://github.com/${REPO}#from-source" ;;
esac

# Interactive only when we actually have a terminal. Piping into bash means
# stdin is the script itself, so prompts have to read from /dev/tty.
INTERACTIVE=1
[ -n "${REVPD_NONINTERACTIVE:-}" ] && INTERACTIVE=0
[ -e /dev/tty ] || INTERACTIVE=0

ask() {
    local prompt=$1 default=${2:-} answer
    if [ "$INTERACTIVE" -eq 0 ]; then
        printf '%s' "$default"
        return
    fi
    if [ -n "$default" ]; then
        printf '%s %s[%s]%s ' "$prompt" "$DIM" "$default" "$R" > /dev/tty
    else
        printf '%s ' "$prompt" > /dev/tty
    fi
    read -r answer < /dev/tty || answer=""
    printf '%s' "${answer:-$default}"
}

ask_secret() {
    local prompt=$1 answer
    printf '%s ' "$prompt" > /dev/tty
    stty -echo < /dev/tty
    read -r answer < /dev/tty || answer=""
    stty echo < /dev/tty
    printf '\n' > /dev/tty
    printf '%s' "$answer"
}

say ""
say "  ${B}Revpd${R} — MFA gateway for RDP with Wake-on-LAN"
say "  ${DIM}https://github.com/${REPO}${R}"
say ""

UPGRADE=0
[ -x "${BIN_DIR}/revpd" ] && UPGRADE=1

# -------------------------------------------------------------- download ---

step "Fetching release"

VERSION=${REVPD_VERSION:-}
if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL --retry 3 --connect-timeout 10 \
        "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' | cut -d'"' -f4) || true

    [ -n "$VERSION" ] || die "could not reach GitHub to find the latest release.
Check the network, or pin one:  REVPD_VERSION=v1.0.0 curl -fsSL … | sudo bash"
fi
ok "version ${VERSION} (linux/${ARCH})"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

TARBALL="revpd_${VERSION#v}_linux_${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

curl -fsSL --retry 3 -o "${TMP}/${TARBALL}" "${BASE}/${TARBALL}" \
    || die "download failed: ${BASE}/${TARBALL}"

# Checksums are published alongside the binaries. A release without them is
# not something we install silently.
if curl -fsSL --retry 3 -o "${TMP}/checksums.txt" "${BASE}/checksums.txt" 2>/dev/null; then
    ( cd "$TMP" && grep " ${TARBALL}\$" checksums.txt | sha256sum -c --status - ) \
        || die "checksum mismatch — the download was corrupted or tampered with"
    ok "checksum verified"
else
    warn "no checksums.txt in this release; skipping verification"
fi

tar -xzf "${TMP}/${TARBALL}" -C "$TMP"
[ -f "${TMP}/revpd" ] || die "the archive does not contain a revpd binary"

# ------------------------------------------------------------- accounts ----

step "Installing"

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    ok "created the ${USER_NAME} system account"
fi

install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$DATA_DIR"
install -d -m 0750 -o root -g "$USER_NAME" "$CONF_DIR"

install -m 0755 "${TMP}/revpd" "${BIN_DIR}/revpd"
ok "${BIN_DIR}/revpd"

# ---------------------------------------------------------------- config ---

if [ ! -f "${CONF_DIR}/.env" ]; then
    step "Generating the master key"

    KEY=$("${BIN_DIR}/revpd" genkey 2>/dev/null | cut -d= -f2)
    [ -n "$KEY" ] || die "could not generate a master key"

    umask 077
    cat > "${CONF_DIR}/.env" <<EOF
# Generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
#
# This key encrypts every enrolled second factor. Back it up somewhere safe.
# Losing it means everyone has to set up their authenticator again.
REVPD_MASTER_KEY=${KEY}
EOF
    chown root:"$USER_NAME" "${CONF_DIR}/.env"
    chmod 0640 "${CONF_DIR}/.env"
    ok "${CONF_DIR}/.env  (keep a backup of this)"
else
    ok "${CONF_DIR}/.env already exists, left untouched"
fi

if [ ! -f "${CONF_DIR}/revpd.yaml" ]; then
    HOSTNAME_VALUE=${REVPD_HOSTNAME:-}
    if [ -z "$HOSTNAME_VALUE" ]; then
        say ""
        say "  The name people will type into their browser and RDP client."
        say "  ${DIM}It is also the WebAuthn identifier, so changing it later"
        say "  invalidates every enrolled passkey.${R}"
        say ""
        HOSTNAME_VALUE=$(ask "  Hostname:" "$(hostname -f 2>/dev/null || hostname)")
    fi

    cat > "${CONF_DIR}/revpd.yaml" <<EOF
# Revpd configuration. Full reference:
# https://github.com/${REPO}/blob/main/deploy/revpd.example.yaml
#
# Secrets belong in ${CONF_DIR}/.env, never here.

data_dir: ${DATA_DIR}

web:
  # The web interface. With relay.listen below, these are the only two ports
  # that need to face the internet.
  #
  # Bind to 127.0.0.1 instead to reach it only through an SSH tunnel.
  listen: ":8443"

  hostname: ${HOSTNAME_VALUE}

  # Empty means a self-signed certificate is generated — the portal never
  # serves plain HTTP. Point these at a real one to stop browser warnings.
  tls_cert: ""
  tls_key: ""

relay:
  # Where RDP clients connect.
  listen: ":3389"

rdp_login:
  # The normal way in: type your password and one-time code straight into
  # the Windows Remote Desktop client, separated by a comma.
  enabled: true

grant:
  ttl: 2m
  reuse_window: 10m
EOF
    chown root:"$USER_NAME" "${CONF_DIR}/revpd.yaml"
    chmod 0640 "${CONF_DIR}/revpd.yaml"
    ok "${CONF_DIR}/revpd.yaml"
else
    ok "${CONF_DIR}/revpd.yaml already exists, left untouched"
fi

# --------------------------------------------------------------- systemd ---

step "Setting up the service"

cat > "$SERVICE" <<'EOF'
[Unit]
Description=Revpd — MFA gateway for RDP with Wake-on-LAN
Documentation=https://github.com/plattnericus/revpd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/revpd serve -c /etc/revpd/revpd.yaml
EnvironmentFile=/etc/revpd/.env
Restart=on-failure
RestartSec=5s

User=revpd
Group=revpd

# Binding 3389 is the only privilege needed. Everything else stays dropped.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/revpd
PrivateTmp=yes
PrivateDevices=yes

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete

UMask=0077
LimitNOFILE=8192
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable revpd >/dev/null 2>&1
ok "revpd.service enabled"

# ----------------------------------------------------------- first setup ---

if [ "$UPGRADE" -eq 1 ]; then
    systemctl restart revpd
    ok "restarted"
    say ""
    say "  ${GREEN}Upgraded to ${VERSION}.${R}"
    say ""
    exit 0
fi

# A gateway with no account cannot be used, so offer to make one now.
if [ "$INTERACTIVE" -eq 1 ]; then
    step "Creating the first administrator"
    say ""

    ADMIN=$(ask "  Username:" "admin")
    while :; do
        PW1=$(ask_secret "  Password (at least 12 characters):")
        if [ "${#PW1}" -lt 12 ]; then
            warn "too short, try again"
            continue
        fi
        PW2=$(ask_secret "  Repeat:")
        [ "$PW1" = "$PW2" ] && break
        warn "they do not match, try again"
    done

    ( set -a; . "${CONF_DIR}/.env"; set +a
      printf '%s' "$PW1" | "${BIN_DIR}/revpd" useradd \
          -c "${CONF_DIR}/revpd.yaml" -u "$ADMIN" -admin -password-stdin >/dev/null )
    unset PW1 PW2
    ok "created ${ADMIN}"

    say ""
    step "Enrolling the second factor"
    say ""
    ( set -a; . "${CONF_DIR}/.env"; set +a
      "${BIN_DIR}/revpd" enroll -c "${CONF_DIR}/revpd.yaml" -u "$ADMIN" )
fi

chown -R "$USER_NAME":"$USER_NAME" "$DATA_DIR"
systemctl start revpd
ok "revpd is running"

# ----------------------------------------------------------- next steps ----

HOST=$(grep -m1 '^  hostname:' "${CONF_DIR}/revpd.yaml" | awk '{print $2}')

say ""
say "  ${GREEN}${B}Done.${R}"
say ""
say "  ${B}1. Add the machine you want to reach${R}"
say "     ${DIM}revpd targetadd -name \"Office PC\" -ip 192.168.1.40 \\"
say "                     -mac aa:bb:cc:dd:ee:ff -for ${ADMIN:-admin}${R}"
say ""
say "  ${B}2. Forward two ports to this server${R}"
say "     ${DIM}3389  Remote Desktop"
say "     8443  web interface"
say "     Nothing else. The target itself stays closed — see deploy/HARDENING.md.${R}"
say ""
say "  ${B}3. Connect${R}"
say "     ${DIM}Remote Desktop → ${HOST}"
say "     Password field: YourPassword,123456${R}"
say ""
say "  Web interface: ${B}https://${HOST}:8443${R}"
say "  ${DIM}Self-signed for now, so the browser will warn once.${R}"
say "  Logs:          ${DIM}journalctl -u revpd -f${R}"
say ""

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
#   REVPD_REPO=owner/name    install from a fork
#   GITHUB_TOKEN=…           raise the API rate limit on a shared address

set -Eeuo pipefail

REPO="${REVPD_REPO:-plattnericus/revpd}"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/revpd"
DATA_DIR="/var/lib/revpd"
SERVICE="/etc/systemd/system/revpd.service"
UPDATE_SERVICE="/etc/systemd/system/revpd-update.service"
UPDATE_PATH="/etc/systemd/system/revpd-update.path"
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

API="https://api.github.com/repos/${REPO}"
RELEASES_PAGE="https://github.com/${REPO}/releases"
INSTALL_CMD="curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# fetch retrieves a URL and reports separately whether the request reached
# GitHub at all (CURL_EXIT) and what GitHub answered (HTTP_STATUS).
#
# `curl -f` collapses those into one exit status, which is why this installer
# used to blame the network for a server that had replied perfectly well.
fetch() {
    local url=$1 out=$2

    # Never empty: `${arr[@]}` on an empty array trips `set -u` on bash 4.3
    # and older, which is still what a few long-lived servers ship.
    local auth=(-H 'X-Revpd-Install: 1')
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

    HTTP_STATUS=000
    CURL_EXIT=0
    HTTP_STATUS=$(curl -sSL --retry 2 --retry-connrefused \
        --connect-timeout 10 --max-time 600 \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: revpd-install' \
        "${auth[@]}" \
        -D "${TMP}/headers" -o "$out" -w '%{http_code}' \
        "$url" 2>"${TMP}/curl.err") || CURL_EXIT=$?
    return 0
}

# network_problem turns a curl exit code into the thing that is actually wrong,
# because "could not reach GitHub" is true of a dozen different faults that
# each need a different fix.
network_problem() {
    local url=$1 detail host
    # curl repeats itself once per retry; one copy is enough.
    detail=$(sort -u "${TMP}/curl.err" 2>/dev/null | head -n1 || true)
    host=$(printf '%s' "$url" | sed -e 's|^[a-z]*://||' -e 's|/.*||')

    local cause
    case "$CURL_EXIT" in
        5)  cause="The proxy named in http_proxy/https_proxy could not be resolved.
  Check those variables, or unset them if this machine does not use a proxy." ;;
        6)  cause="The name ${host} could not be resolved — DNS is not answering.
  Check:  cat /etc/resolv.conf   and   getent hosts ${host}" ;;
        7)  cause="The connection was refused or dropped before any data was exchanged.
  Usually an outbound firewall, or a network that requires a proxy.
  Check:  curl -v https://api.github.com   and any http_proxy setting." ;;
        28) cause="The request timed out. The route to GitHub is very slow or losing packets." ;;
        35|59|60|77|91)
            cause="The TLS handshake failed. The three usual causes:
    • the system clock is wrong          — check:  date -u
    • the CA certificates are missing    — fix:    install ca-certificates
    • a filtering proxy is intercepting TLS and its certificate is not trusted" ;;
        56) cause="The connection was reset part-way through the transfer." ;;
        *)  cause="curl gave up with exit code ${CURL_EXIT}." ;;
    esac

    die "could not reach GitHub.

  URL:   ${url}
  Cause: ${cause}${detail:+
  curl:  ${detail}}

  Nothing has been installed or changed. Run this again once the network works."
}

# The responses used here are small and fixed in shape, so a couple of greps
# beat requiring jq or python on a freshly imaged server.
json_string() {
    grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$2" 2>/dev/null \
        | head -n1 | sed 's/.*:[[:space:]]*"\(.*\)"$/\1/' || true
}
asset_urls() {
    # Strip the key and the surrounding quotes rather than matching the value
    # against an expected shape: an assumption about what the URL looks like is
    # one more thing that can silently stop matching.
    grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null \
        | sed -e 's/^[^:]*:[[:space:]]*"//' -e 's/"$//' || true
}
tag_names() {
    grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null \
        | sed 's/.*"\(.*\)"$/\1/' || true
}

# api_checked handles every answer that means the same thing on every endpoint.
# 200 and 404 are left to the caller: what a missing thing means depends on
# what was asked for.
api_checked() {
    local url=$1 body=$2
    [ "$CURL_EXIT" -eq 0 ] || network_problem "$url"

    local msg
    msg=$(json_string message "$body")

    case "$HTTP_STATUS" in
        200|404) return 0 ;;
        401) die "GitHub rejected GITHUB_TOKEN (401).
  The token is expired, revoked or malformed. Unset it to continue anonymously:
    unset GITHUB_TOKEN" ;;
        403|429)
            local remaining reset
            remaining=$(grep -i '^x-ratelimit-remaining:' "${TMP}/headers" 2>/dev/null | tr -d '\r' | awk '{print $2}' | tail -n1 || true)
            reset=$(grep -i '^x-ratelimit-reset:' "${TMP}/headers" 2>/dev/null | tr -d '\r' | awk '{print $2}' | tail -n1 || true)

            if [ "${remaining:-1}" = "0" ]; then
                local when="shortly"
                [ -n "$reset" ] && when=$(date -d "@${reset}" '+%H:%M:%S %Z' 2>/dev/null || echo "shortly")
                die "GitHub's API rate limit for this IP address is used up (403).

  Anonymous requests are limited to 60 per hour and counted per address, so a
  shared or carrier-grade-NAT address runs out without you doing anything.

  Any one of these gets you moving again:
    • wait until ${when}, then run the same command
    • raise the limit with a token (any classic token, no scopes needed):
        GITHUB_TOKEN=ghp_… ${INSTALL_CMD}
    • skip the API entirely by naming the version:
        REVPD_VERSION=v1.0.0 ${INSTALL_CMD}"
            fi
            die "GitHub refused the request (403).${msg:+
  It said: ${msg}}
  If ${REPO} is a private repository, export a GITHUB_TOKEN that can read it." ;;
        5*) die "GitHub itself is failing (HTTP ${HTTP_STATUS}).${msg:+
  It said: ${msg}}
  This is not a problem on your machine. Check https://www.githubstatus.com
  and run the same command again afterwards." ;;
        *)  die "unexpected answer from GitHub (HTTP ${HTTP_STATUS}) for
  ${url}${msg:+
  It said: ${msg}}" ;;
    esac
}

# no_release_found explains a 404 from releases/latest, which has three quite
# different causes that the bare status code hides.
no_release_found() {
    local list="${TMP}/all.json"

    fetch "${API}" "${TMP}/repo.json"
    api_checked "${API}" "${TMP}/repo.json"
    if [ "$HTTP_STATUS" = "404" ]; then
        die "the repository ${REPO} does not exist, or is private.

  Check the spelling, or if it is private export a token that can read it:
    GITHUB_TOKEN=ghp_… ${INSTALL_CMD}"
    fi

    fetch "${API}/releases?per_page=100" "$list"
    api_checked "${API}/releases" "$list"

    local tags
    tags=$(tag_names "$list")

    if [ -z "$tags" ]; then
        die "${REPO} has not published any release yet.

  There is nothing to download: this installer only ever installs released
  builds, and none exist.

  Your options:
    • watch ${RELEASES_PAGE} and install once a release appears
    • build it yourself from source (needs Go and Node.js):
        https://github.com/${REPO}#from-source
    • run it in Docker instead:
        https://github.com/${REPO}#docker"
    fi

    die "${REPO} has releases, but none of them is a published, final release.

  GitHub's \"latest release\" deliberately skips drafts and pre-releases, so
  this installer cannot pick one on its own.

  Tags that do exist:
$(printf '%s\n' "$tags" | sed 's/^/    /')

  Name the one you want:
    REVPD_VERSION=$(printf '%s\n' "$tags" | head -n1) ${INSTALL_CMD}

  Full list with their files: ${RELEASES_PAGE}"
}

step "Fetching release"

RELEASE="${TMP}/release.json"
VERSION=${REVPD_VERSION:-}

if [ -n "$VERSION" ]; then
    fetch "${API}/releases/tags/${VERSION}" "$RELEASE"
    api_checked "${API}/releases/tags/${VERSION}" "$RELEASE"

    if [ "$HTTP_STATUS" = "404" ]; then
        fetch "${API}/releases?per_page=100" "${TMP}/all.json"
        api_checked "${API}/releases" "${TMP}/all.json"
        AVAILABLE=$(tag_names "${TMP}/all.json")

        die "there is no release tagged ${VERSION} in ${REPO}.
${AVAILABLE:+
  These tags exist:
$(printf '%s\n' "$AVAILABLE" | sed 's/^/    /')
}
  REVPD_VERSION has to match a tag exactly, including the leading v.
  Full list: ${RELEASES_PAGE}"
    fi
else
    fetch "${API}/releases/latest" "$RELEASE"
    api_checked "${API}/releases/latest" "$RELEASE"
    [ "$HTTP_STATUS" = "404" ] && no_release_found

    VERSION=$(json_string tag_name "$RELEASE")
    [ -n "$VERSION" ] || die "GitHub returned a release for ${REPO} with no tag_name in it.
  This should not happen. Please report it at https://github.com/${REPO}/issues
  and install a specific version meanwhile:
    REVPD_VERSION=v1.0.0 ${INSTALL_CMD}"
fi

ok "version ${VERSION} (linux/${ARCH})"

# The archive is located through the release's own asset list rather than by
# assembling a download URL and hoping. A missing file then fails here, with
# the list of what is actually published, instead of as a bare 404 from a URL
# nobody can check by eye.
TARBALL="revpd_${VERSION#v}_linux_${ARCH}.tar.gz"
ASSETS=$(asset_urls "$RELEASE")
ASSET_NAMES=$(printf '%s\n' "$ASSETS" | sed 's|.*/||' | grep -v '^$' || true)

if [ -z "$ASSET_NAMES" ]; then
    die "release ${VERSION} exists, but has no files attached to it.

  A Revpd release ships one archive per architecture plus checksums.txt.
  This tag carries none, so there is genuinely nothing to download — the
  release was created without ever building the artefacts.

  Nothing on your machine has been changed. What you can do:

    • install a release that does have files — the pages under
      ${RELEASES_PAGE} show the file list for each one:
        REVPD_VERSION=vX.Y.Z ${INSTALL_CMD}

    • or build from source (needs Go and Node.js):
        https://github.com/${REPO}#from-source

  If ${REPO} is yours: the release workflow never ran for this tag. Run it
  from the Actions tab against ${VERSION}, or push the tag again."
fi

ASSET_URL=$(printf '%s\n' "$ASSETS" | grep -m1 "/${TARBALL}\$" || true)

if [ -z "$ASSET_URL" ]; then
    die "release ${VERSION} has files, but none built for linux/${ARCH}.

  This machine reports $(uname -m), so the archive it needs is:
    ${TARBALL}

  What ${VERSION} actually contains:
$(printf '%s\n' "$ASSET_NAMES" | sed 's/^/    /')

  If the list above has archives for other architectures only, this release
  simply was not built for ${ARCH}. Pick a release that was, or build from
  source: https://github.com/${REPO}#from-source"
fi

fetch "$ASSET_URL" "${TMP}/${TARBALL}"
[ "$CURL_EXIT" -eq 0 ] || network_problem "$ASSET_URL"
[ "$HTTP_STATUS" = "200" ] || die "downloading ${TARBALL} failed with HTTP ${HTTP_STATUS}.

  URL: ${ASSET_URL}

  The release lists this file, so it existed a moment ago. A proxy that
  rewrites downloads, or a transient GitHub fault, would both look like this.
  Running the command again is worth a try."

ok "downloaded ${TARBALL} ($(du -h "${TMP}/${TARBALL}" | cut -f1))"

# Checksums are published alongside the archives. A release without them is
# not something we install silently.
CHECKSUM_URL=$(printf '%s\n' "$ASSETS" | grep -m1 '/checksums\.txt$' || true)

if [ -n "$CHECKSUM_URL" ]; then
    fetch "$CHECKSUM_URL" "${TMP}/checksums.txt"
    [ "$HTTP_STATUS" = "200" ] || die "checksums.txt is listed in release ${VERSION} but could not be
  downloaded (HTTP ${HTTP_STATUS}). Refusing to install an unverified binary."

    EXPECTED=$(grep " \{1,2\}${TARBALL}\$" "${TMP}/checksums.txt" | awk '{print $1}' | head -n1 || true)
    if [ -z "$EXPECTED" ]; then
        die "checksums.txt in release ${VERSION} has no entry for ${TARBALL}.
  Refusing to install a binary that the release does not vouch for."
    fi

    ACTUAL=$(sha256sum "${TMP}/${TARBALL}" | awk '{print $1}')
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        die "checksum mismatch on ${TARBALL} — refusing to install it.

  expected: ${EXPECTED}
  actual:   ${ACTUAL}

  The download was corrupted in transit, or it was tampered with. A proxy that
  caches or rewrites downloads is the most common innocent explanation.
  Nothing was installed."
    fi
    ok "checksum verified"
else
    warn "release ${VERSION} publishes no checksums.txt — the download could not be verified"
fi

tar -xzf "${TMP}/${TARBALL}" -C "$TMP" \
    || die "${TARBALL} downloaded but could not be unpacked — the file is not a
  valid gzip archive. That usually means a captive portal or proxy returned a
  login page instead of the file. Nothing was installed."

[ -f "${TMP}/revpd" ] || die "the archive ${TARBALL} unpacked, but there is no revpd binary
  at the root of it. This release is built wrongly rather than damaged in
  transit — the checksum above matched.

  Nothing was installed. Please report it at https://github.com/${REPO}/issues"

chmod +x "${TMP}/revpd"
BINARY_VERSION=$("${TMP}/revpd" version 2>/dev/null || true)
[ -n "$BINARY_VERSION" ] || die "the downloaded revpd binary does not run on this machine.

  It unpacked cleanly, so the download was fine — but executing it produced
  nothing. On a $(uname -m) host that normally means the archive holds a build
  for a different architecture, or the kernel is older than the build targets.

  Nothing was installed. Please report it at https://github.com/${REPO}/issues"
ok "${BINARY_VERSION} runs here"

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

update:
  # Check GitHub for newer releases and show them in the dashboard.
  enabled: true

  # Install them without being asked. Off here because installing restarts
  # the service and drops any live session — turn it on in the dashboard,
  # under Settings, once you are happy with that.
  auto_install: false

  # Never restart while somebody is connected.
  only_when_idle: true

  check_interval: 6h
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
ProcSubset=pid
RemoveIPC=yes
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

# The gateway runs unprivileged with /usr mounted read-only, so it cannot
# replace its own binary. These two units are the part that can: the service
# downloads and verifies a release, then asks for it to be installed, and this
# picks the request up as root.
cat > "$UPDATE_SERVICE" <<'EOF'
[Unit]
Description=Install the staged Revpd update
Documentation=https://github.com/plattnericus/revpd

[Service]
Type=oneshot
ExecStart=/usr/local/bin/revpd update apply-staged

User=root
ReadWritePaths=/usr/local/bin /var/lib/revpd
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# The applier waits for the restarted service to prove it stays up, and rolls
# back if it does not. That wait has to fit inside this.
TimeoutStartSec=300
EOF

cat > "$UPDATE_PATH" <<'EOF'
[Unit]
Description=Watch for a Revpd update waiting to be installed
Documentation=https://github.com/plattnericus/revpd

[Path]
PathExists=/var/lib/revpd/update/apply.request
Unit=revpd-update.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable revpd >/dev/null 2>&1
ok "revpd.service enabled"

if systemctl enable --now revpd-update.path >/dev/null 2>&1; then
    ok "revpd-update.path enabled — updates can be installed from the dashboard"
else
    warn "revpd-update.path could not be enabled; updates will have to be installed with \`sudo revpd update install\`"
fi

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

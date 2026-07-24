# Reproducible build: the frontend is compiled, embedded into the binary, and
# the result runs on a distroless base with no shell and no package manager.

# ─── frontend ───────────────────────────────────────────────────────────────
FROM node:22-alpine AS web

WORKDIR /src/web

# Copy the manifests first so a dependency install is cached across code edits.
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
RUN npm run build


# ─── binary ─────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The build embeds internal/web/dist, so the frontend has to land there first.
COPY --from=web /src/internal/web/dist ./internal/web/dist

ARG VERSION=docker

# CGO off keeps it static; trimpath and -s -w keep it small and reproducible.
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /revpd ./cmd/revpd


# ─── runtime ────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /revpd /usr/local/bin/revpd

# Binding 3389 and 443 needs a privileged port, so the container is normally
# run with --cap-add NET_BIND_SERVICE rather than as root.
USER nonroot:nonroot

VOLUME ["/var/lib/revpd"]
EXPOSE 3389 8443

ENTRYPOINT ["/usr/local/bin/revpd"]
CMD ["serve", "-c", "/etc/revpd/revpd.yaml"]

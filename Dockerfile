# Multi-stage build shared by all three binaries (gateway, seed, upstream).
# Select which one to produce with --build-arg BINARY=gateway|seed|upstream.

FROM golang:1.24-alpine AS build
ARG BINARY=gateway
WORKDIR /src

# Dependencies first so they layer-cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/app ./cmd/${BINARY}

# Distroless: no shell, no package manager, nothing an attacker who lands
# remote code execution in the app can pivot to. The image runs as its
# non-root "nonroot" user by default.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]

# syntax=docker/dockerfile:1.7
# Build context is the repository root.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentinel-panel ./cmd/panel \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck
# The panel serves these to the one-line agent installer (/install.sh, /download/...).
RUN mkdir -p /out/downloads \
 && for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" -o /out/downloads/sentinel-agent-linux-$arch ./cmd/agent; \
    done \
 && cd /out/downloads && sha256sum sentinel-agent-linux-* > SHA256SUMS

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sentinel-panel /opt/sentinel/bin/sentinel-panel
COPY --from=build /out/healthcheck /opt/sentinel/bin/healthcheck
COPY --from=web /src/web/dist /opt/sentinel/web
COPY --from=build /out/downloads /opt/sentinel/downloads
ENV PANEL_WEB_DIR=/opt/sentinel/web
ENV PANEL_DOWNLOAD_DIR=/opt/sentinel/downloads
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/opt/sentinel/bin/sentinel-panel"]

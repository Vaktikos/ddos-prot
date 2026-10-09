# Common development tasks. Requires Go 1.27+, Node 22+ and, for integration tests, PostgreSQL 16.
GO        ?= go
VERSION   ?= 0.1.0
BIN       := bin
SS_TEST_DSN ?=

.PHONY: all build test test-integration test-nft web web-build clean vet vuln

all: build test web-build

build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN)/sentinel-agent ./cmd/agent
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN)/sentinel-panel ./cmd/panel
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN)/sentinel-healthcheck ./cmd/healthcheck

vet:
	$(GO) vet ./...
	test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)

# Unit tests need no database and no privileges.
test: vet
	$(GO) test -count=1 -race ./...

# Requires SS_TEST_DSN, e.g. "host=127.0.0.1 port=5432 user=postgres dbname=sentinel_test sslmode=disable".
# WARNING: the test recreates the public schema of that database.
test-integration:
	@test -n "$(SS_TEST_DSN)" || (echo "SS_TEST_DSN ist nicht gesetzt" && exit 1)
	SS_TEST_DSN="$(SS_TEST_DSN)" $(GO) test -count=1 -race -p 1 ./internal/store/ ./internal/panel/

# Loads a test table into the live kernel. Run only on a disposable host, as root.
test-nft:
	SS_NFT_INTEGRATION=1 $(GO) test -count=1 -run Integration ./internal/nft/

web:
	cd web && npm ci && npm run build

web-build:
	cd web && npm ci --no-audit --no-fund && npm run build

clean:
	rm -rf $(BIN) web/dist

# Needs network access to vuln.go.dev. Also run in CI.
vuln:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
	cd web && npm audit --audit-level=moderate

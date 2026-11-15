# NDAgent Makefile

VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0-unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Release builds pass -trimpath on their go build lines: the binary records
# module-relative file names, not the paths of the machine that built it.
LDFLAGS := -ldflags "-s -w -X github.com/netdefense-io/ndagent/pkg/version.Version=$(VERSION) \
	-X github.com/netdefense-io/ndagent/pkg/version.BuildTime=$(BUILD_TIME) \
	-X github.com/netdefense-io/ndagent/pkg/version.GitCommit=$(GIT_COMMIT)"

LDFLAGS_DEBUG := -ldflags "-X github.com/netdefense-io/ndagent/pkg/version.Version=$(VERSION) \
	-X github.com/netdefense-io/ndagent/pkg/version.BuildTime=$(BUILD_TIME) \
	-X github.com/netdefense-io/ndagent/pkg/version.GitCommit=$(GIT_COMMIT)"

.PHONY: all build build-debug build-freebsd build-freebsd-debug build-darwin build-all clean test lint fmt deps build-connect build-connect-freebsd test-connect

all: build

build:
	go build -trimpath $(LDFLAGS) -o bin/ndagent ./cmd/ndagent

build-debug:
	go build $(LDFLAGS_DEBUG) -o bin/ndagent ./cmd/ndagent

build-freebsd:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath $(LDFLAGS) -o bin/ndagent-freebsd-amd64 ./cmd/ndagent

build-freebsd-debug:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS_DEBUG) -o bin/ndagent-freebsd-amd64 ./cmd/ndagent

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath $(LDFLAGS) -o bin/ndagent-darwin-amd64 ./cmd/ndagent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath $(LDFLAGS) -o bin/ndagent-darwin-arm64 ./cmd/ndagent

build-all: build-freebsd build-darwin

# ndagent-connect, the companion of the "direct-peer + encrypted relay"
# transport: a module of its own under connect/, built with the Go release
# its own go.mod names (go downloads it on first use) and the tags in
# connect/build-tags.txt. It carries the agent's version: the agent refuses a
# companion whose version is not its own, so build the two from one checkout.
CONNECT_TAGS := $(shell cat connect/build-tags.txt 2>/dev/null)
CONNECT_LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT)"

build-connect:
	cd connect && go build -trimpath -tags "$(CONNECT_TAGS)" $(CONNECT_LDFLAGS) -o ../bin/ndagent-connect ./cmd/ndagent-connect

build-connect-freebsd:
	cd connect && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -tags "$(CONNECT_TAGS)" $(CONNECT_LDFLAGS) -o ../bin/ndagent-connect-freebsd-amd64 ./cmd/ndagent-connect

# The companion's own tests, then the agent's side against the companion just
# built. Everything runs against a relay inside the tests.
test-connect: build-connect
	cd connect && go test -race ./...
	NDAGENT_CONNECT_BIN=$(CURDIR)/bin/ndagent-connect NDAGENT_CONNECT_VERSION=$(VERSION) go test -count=1 -run RealCompanion ./internal/directpeer/

test:
	go test -v -race ./...

lint:
	golangci-lint run

fmt:
	go fmt ./...

clean:
	rm -rf bin/

deps:
	go mod download
	go mod tidy

# NDAgent Makefile

VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0-unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS := -ldflags "-s -w -X github.com/netdefense-io/ndagent/pkg/version.Version=$(VERSION) \
	-X github.com/netdefense-io/ndagent/pkg/version.BuildTime=$(BUILD_TIME) \
	-X github.com/netdefense-io/ndagent/pkg/version.GitCommit=$(GIT_COMMIT)"

LDFLAGS_DEBUG := -ldflags "-X github.com/netdefense-io/ndagent/pkg/version.Version=$(VERSION) \
	-X github.com/netdefense-io/ndagent/pkg/version.BuildTime=$(BUILD_TIME) \
	-X github.com/netdefense-io/ndagent/pkg/version.GitCommit=$(GIT_COMMIT)"

.PHONY: all build build-debug build-freebsd build-freebsd-debug build-darwin build-all clean test lint fmt deps

all: build

build:
	go build $(LDFLAGS) -o bin/ndagent ./cmd/ndagent

build-debug:
	go build $(LDFLAGS_DEBUG) -o bin/ndagent ./cmd/ndagent

build-freebsd:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS) -o bin/ndagent-freebsd-amd64 ./cmd/ndagent

build-freebsd-debug:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS_DEBUG) -o bin/ndagent-freebsd-amd64 ./cmd/ndagent

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/ndagent-darwin-amd64 ./cmd/ndagent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/ndagent-darwin-arm64 ./cmd/ndagent

build-all: build-freebsd build-darwin

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

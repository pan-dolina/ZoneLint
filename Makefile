# Makefile for ZoneLint

GO ?= go
BIN := dist/zonelint

.PHONY: all build test race lint fmt vet fuzz-bench clean release check-deps

all: build

build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/zonelint

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

staticcheck:
	$(GO) install honnef.co/go/tools/cmd/staticcheck@2024.1.1
	staticcheck ./...

gosec:
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -conf gosec.json ./... || true

govulncheck:
	$(GO) install golang.org/x/v/cmd/govulncheck@latest
	govulncheck ./...

lint: vet staticcheck gosec govulncheck

check-deps:
	scripts/check-dependencies.sh

release:
	scripts/build-release.sh

clean:
	rm -rf dist/

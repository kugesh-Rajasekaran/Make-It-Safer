# Make-It-Safer build targets. Run `make check` before committing
# (the pre-commit hook does this for you: git config core.hooksPath .githooks).

GO        ?= go
BIN       := bin/mis
MODULE    := github.com/kugesh-rajasekaran/make-it-safer
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X $(MODULE)/internal/cli.version=$(VERSION)

.PHONY: build test test-integration lint fmt fmt-check check clean

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/mis

test:
	$(GO) test -race ./...

# Needs Docker: starts throwaway Ubuntu and Debian SSH servers.
test-integration:
	$(GO) test -tags integration -count=1 -timeout 30m ./...

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

fmt-check:
	@out="$$(golangci-lint fmt --diff ./...)"; if [ -n "$$out" ]; then echo "$$out"; echo "run: make fmt"; exit 1; fi

check: fmt-check lint test

clean:
	rm -rf bin

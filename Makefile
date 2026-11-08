# Make-It-Safer build targets. Run `make check` before committing
# (the pre-commit hook does this for you: git config core.hooksPath .githooks).

GO        ?= go
BIN       := bin/mis
MODULE    := github.com/kugesh-rajasekaran/make-it-safer
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X $(MODULE)/internal/cli.version=$(VERSION)

PREFIX    ?= $(HOME)/.local
HELPER    := Make-It-Safer Notifier.app
OS        := $(shell uname -s)

.PHONY: build test test-integration lint fmt fmt-check check clean macos-helper install uninstall

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

# macOS only: builds "Make-It-Safer Notifier.app" into macos/build/.
macos-helper:
	./macos/build.sh

# Installs mis into $(PREFIX)/bin and, on macOS, the notification helper into
# ~/Applications. An installed background service restarts with the new mis.
install: build
	install -d "$(PREFIX)/bin"
	install -m 0755 $(BIN) "$(PREFIX)/bin/mis"
ifeq ($(OS),Darwin)
	./macos/build.sh
	mkdir -p "$(HOME)/Applications"
	rm -rf "$(HOME)/Applications/$(HELPER)"
	cp -R "macos/build/$(HELPER)" "$(HOME)/Applications/"
endif
	@if "$(PREFIX)/bin/mis" service status --json 2>/dev/null | grep -q '"installed":true'; then "$(PREFIX)/bin/mis" service install; fi
	@case ":$$PATH:" in *":$(PREFIX)/bin:"*) ;; *) echo "Add $(PREFIX)/bin to your PATH (e.g. in ~/.zshrc or ~/.bashrc)." ;; esac
	@echo "Installed $(PREFIX)/bin/mis. New here? Run: mis init"

# Removes the background service, mis and the helper. Your settings and
# encrypted key stay (see docs/user-guide.md to delete them).
uninstall:
	-@"$(PREFIX)/bin/mis" service uninstall 2>/dev/null
	rm -f "$(PREFIX)/bin/mis"
ifeq ($(OS),Darwin)
	rm -rf "$(HOME)/Applications/$(HELPER)"
endif
	@echo "Removed mis. Your settings and encrypted key are still in place."

clean:
	rm -rf bin macos/build

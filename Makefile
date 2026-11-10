# ctxward build. No network access is used by any target (Go module cache must already be populated,
# and go.mod is expected to have no third-party requirements).
SHELL := /bin/sh
GO      ?= go
PKG     := ./cmd/ctxward
GOFLAGS_BUILD := -trimpath -buildvcs=false
LDFLAGS := -s -w
TARGETS := linux-amd64 linux-arm64 darwin-arm64 darwin-amd64 windows-amd64

HOSTOS   := $(shell $(GO) env GOOS)
HOSTARCH := $(shell $(GO) env GOARCH)
HOSTEXT  := $(if $(filter windows,$(HOSTOS)),.exe,)

export CGO_ENABLED := 0
export GOFLAGS := -mod=readonly
export GOPROXY := off

.PHONY: build dist checksums verify test plugin-test fmt clean

# Current platform, placed where plugin/scripts/ctxward-launch expects it.
build:
	mkdir -p plugin/libexec/$(HOSTOS)-$(HOSTARCH)
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS_BUILD) -ldflags '$(LDFLAGS)' \
		-o plugin/libexec/$(HOSTOS)-$(HOSTARCH)/ctxward$(HOSTEXT) $(PKG)

# Cross-compile the five supported targets into plugin/libexec/<os>-<arch>/.
dist:
	@for t in $(TARGETS); do \
		os=$${t%-*}; arch=$${t#*-}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
		mkdir -p plugin/libexec/$$t; \
		echo "build $$t"; \
		GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS_BUILD) -ldflags '$(LDFLAGS)' \
			-o plugin/libexec/$$t/ctxward$$ext $(PKG) || exit 1; \
	done

# SHA256SUMS over the built binaries (paths relative to the repo root).
checksums:
	@rm -f SHA256SUMS
	@for t in $(TARGETS); do \
		f=plugin/libexec/$$t/ctxward; [ -f $$f.exe ] && f=$$f.exe; \
		[ -f $$f ] || { echo "missing $$f (run make dist)" >&2; exit 1; }; \
		if command -v sha256sum >/dev/null 2>&1; then sha256sum $$f >> SHA256SUMS; \
		else shasum -a 256 $$f >> SHA256SUMS; fi; \
	done
	@cat SHA256SUMS

# Rebuild everything and fail if it differs from what is committed. Builds are reproducible
# (-trimpath, -buildvcs=false so no git state is embedded, CGO off, pinned Go version), so a difference means the source or toolchain moved.
# The old binaries are deleted first: `go build -o` leaves an existing file alone when its build ID
# matches, so a tampered committed binary would otherwise survive the rebuild and pass.
verify:
	@for t in $(TARGETS); do rm -f plugin/libexec/$$t/ctxward plugin/libexec/$$t/ctxward.exe; done
	@$(MAKE) --no-print-directory dist checksums
	git diff --exit-code -- SHA256SUMS plugin/libexec

test:
	$(GO) vet ./...
	CGO_ENABLED=1 $(GO) test -race ./...

# Drive the hooks through the launcher; `make plugin-test ARGS=live` also starts Claude Code.
plugin-test:
	scripts/plugin-test.sh $(ARGS)

fmt:
	$(GO) fmt ./...

clean:
	rm -rf plugin/libexec/linux-amd64 plugin/libexec/linux-arm64 plugin/libexec/darwin-arm64 plugin/libexec/darwin-amd64 plugin/libexec/windows-amd64 SHA256SUMS

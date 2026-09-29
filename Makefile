.PHONY: help \
	build \
	build-linux \
	cross \
	install \
	test \
	test-race \
	e2e \
	vet \
	lint \
	fmt \
	fmt-check \
	tidy \
	tidy-check \
	verify \
	verify-linux \
	clean

.DEFAULT_GOAL := help

# Strict shell: fail on the first error, catch pipeline errors, reject unset variables.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules

# Every Go command runs module-local: a developer go.work must never change
# what the gates build or test.
export GOWORK := off

# The binary name matches the cobra root command (`Use: "tplaiter"`).
NAME    := tplaiter
BIN     := bin/$(NAME)
PKG     := github.com/tplAIter/tplaiter

# Version compiled into the binary (overridden by release tooling: make build VERSION=vX.Y.Z).
VERSION ?= dev

# Installed-registration pins (see internal/cmd/trust_launch.go). They are empty
# by default, which yields a stock binary that refuses trust-gated commands with
# TRUST_ANCHOR_MISSING. The OSS registration flow (U02) sets them.
REGISTRATION_PATH   ?=
REGISTRATION_SHA256 ?=

LDFLAGS := -s -w -X $(PKG)/internal/cmd.version=$(VERSION)
ifneq ($(strip $(REGISTRATION_PATH)),)
LDFLAGS += -X $(PKG)/internal/cmd.installedRegistrationPath=$(REGISTRATION_PATH)
endif
ifneq ($(strip $(REGISTRATION_SHA256)),)
LDFLAGS += -X $(PKG)/internal/cmd.installedRegistrationSHA256=$(REGISTRATION_SHA256)
endif

# Installation layout (GNU conventions; DESTDIR supports staged installs).
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=

# Long-running gates share one generous per-package timeout: the trust store
# and approved-runner suites spawn real child processes and SQLite databases.
TEST_TIMEOUT ?= 30m

# Supported build targets. Windows is informational only (deferred, P21).
CROSS_TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

# Utils ################################################################################################################

help: ## Show this menu.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

# Code Quality #########################################################################################################

vet: ## Run go vet for both modules (host) and the root module for GOOS=linux.
	go vet ./...
	GOOS=linux go vet ./...
	cd tests && go vet ./...

lint: ## Run golangci-lint for both modules (each has its own .golangci.yml).
	golangci-lint run ./...
	cd tests && golangci-lint run ./...

fmt: ## Format code with gofumpt.
	gofumpt -w .

# Check git-tracked plus untracked-but-not-ignored Go files instead of walking
# the tree (`gofumpt -l .`): a Go module cache inside the worktree (for example
# .cache/go/pkg/mod) would otherwise list thousands of dependency files. CI only
# sees committed files; locally, new files are checked before they are added.
fmt-check: ## Check formatting (gofumpt) without changing files.
	@diff <(echo -n) <(git ls-files -z --cached --others --exclude-standard -- '*.go' | xargs -0 -r gofumpt -l)

tidy: ## go mod tidy for both modules.
	go mod tidy
	cd tests && go mod tidy

tidy-check: ## Fail if go.mod/go.sum of either module is not tidy.
	go mod tidy -diff
	cd tests && go mod tidy -diff

# Tests ################################################################################################################

test: ## Run unit tests (-cover).
	go test -count=1 -timeout $(TEST_TIMEOUT) -cover ./...

test-race: ## Run unit tests with the race detector.
	go test -race -count=1 -timeout $(TEST_TIMEOUT) ./...

e2e: ## Run the e2e harness (tests/, a separate black-box module over the binary).
	cd tests && go test -count=1 -timeout $(TEST_TIMEOUT) ./...

# Build ################################################################################################################

build: ## Build the tplaiter binary in bin/.
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .
	@echo "built $(BIN) (version=$(VERSION))"

build-linux: ## Compile every package for GOOS=linux (amd64 and arm64).
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=linux GOARCH=arm64 go build ./...

cross: ## Compile every package for all supported targets (windows is informational).
	@for target in $(CROSS_TARGETS); do \
		echo "go build ./... ($$target)"; \
		GOOS=$${target%/*} GOARCH=$${target#*/} go build ./...; \
	done
	@echo "go build ./... (windows/amd64, informational)"
	-GOOS=windows GOARCH=amd64 go build ./... || echo "windows/amd64: not supported yet (deferred)"

install: build ## Install the binary into $(DESTDIR)$(BINDIR) (PREFIX=/usr/local by default).
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(BIN) "$(DESTDIR)$(BINDIR)/$(NAME)"
	@echo "installed $(DESTDIR)$(BINDIR)/$(NAME)"

clean: ## Remove build artifacts.
	rm -rf bin dist

# Aggregate gates ######################################################################################################

verify: build build-linux vet fmt-check tidy-check test-race e2e lint ## Run every canonical gate (host).

# verify-linux runs inside a plain golang image with a read-only module cache
# mounted (no gofumpt or golangci-lint there; those run on the host). VCS
# stamping is disabled because a linked worktree's .git points outside the
# mounted directory.
verify-linux: export GOFLAGS += -buildvcs=false
verify-linux: ## Linux gate for Docker (build, vet, test-race, e2e; no lint/fmt).
	go build ./...
	go vet ./...
	cd tests && go vet ./...
	go test -race -count=1 -timeout $(TEST_TIMEOUT) ./...
	cd tests && go test -count=1 -timeout $(TEST_TIMEOUT) ./...

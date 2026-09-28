.PHONY: help \
	build \
	test \
	e2e \
	lint \
	fmt \
	fmt-check \
	tidy \
	clean

.DEFAULT_GOAL := help

# Strict shell: fail on the first error, catch pipeline errors, reject unset variables.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules

BIN     := bin/tplater
PKG     := github.com/tplAIter/tplaiter

# Version compiled into the binary (overridden in CI: make build VERSION=vX.Y.Z).
VERSION ?= dev
LDFLAGS := -s -w -X $(PKG)/internal/cmd.version=$(VERSION)

# Utils ################################################################################################################

help: ## Show this menu.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

# Code Quality #########################################################################################################

lint: ## Run golangci-lint.
	golangci-lint run ./...

fmt: ## Format code with gofumpt.
	gofumpt -w .

# Check only git-tracked files, not the whole tree (`gofumpt -l .`): in CI the cache
# The Go cache may be inside the worktree; traversing the whole tree
# would enter .cache/go/pkg/mod and
# list thousands of unformatted dependency files.
# git ls-files covers both modules (root and tests/) and ignores
# untracked directories. Leave fmt untouched: local .cache is absent, and
# dependencies are not rewritten without a nonstandard GOPATH.
fmt-check: ## Check formatting (gofumpt) without changing files.
	@diff <(echo -n) <(git ls-files -z '*.go' | xargs -0 -r gofumpt -l)

test: ## Run tests (-race -cover).
	go test -race -cover ./...

e2e: ## Run the e2e harness (tests/, a separate black-box module over the binary).
	cd tests && go test ./... -count=1

tidy: ## go mod tidy.
	go mod tidy

# Build ################################################################################################################

build: ## Build the tplater binary in bin/.
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .
	@echo "built $(BIN) (version=$(VERSION))"

clean: ## Remove build artifacts.
	rm -rf bin

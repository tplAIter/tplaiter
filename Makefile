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

# Строгий shell: падаем на первой ошибке, ловим ошибки в пайпах, ругаемся на unset-переменные.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --no-builtin-rules

BIN     := bin/tplater
PKG     := github.com/tplAIter/tplaiter

# Версия для вкомпиливания в бинарник (переопределяется в CI: make build VERSION=vX.Y.Z).
VERSION ?= dev
LDFLAGS := -s -w -X $(PKG)/internal/cmd.version=$(VERSION)

# Utils ################################################################################################################

help: ## Показать это меню.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

# Code Quality #########################################################################################################

lint: ## Прогнать golangci-lint.
	golangci-lint run ./...

fmt: ## Отформатировать код через gofumpt.
	gofumpt -w .

# Проверяем только файлы под git, а не всё дерево (`gofumpt -l .`): в CI кэш
# Go-кэш может находиться внутри рабочей директории — обход всего дерева
# пролезал бы в .cache/go/pkg/mod и
# перечислял тысячи «неотформатированных» файлов чужих зависимостей.
# git ls-files покрывает оба модуля (корень и tests/) и игнорирует любые
# неотслеживаемые каталоги. Цель fmt не трогаем: локально .cache нет, а
# перезапись файлов зависимостей она и так не делает без нестандартного GOPATH.
fmt-check: ## Проверить форматирование (gofumpt), не изменяя файлы.
	@diff <(echo -n) <(git ls-files -z '*.go' | xargs -0 -r gofumpt -l)

test: ## Прогнать тесты (-race -cover).
	go test -race -cover ./...

e2e: ## Прогнать e2e-харнесс (tests/, отдельный модуль — чёрный ящик поверх бинарника).
	cd tests && go test ./... -count=1

tidy: ## go mod tidy.
	go mod tidy

# Build ################################################################################################################

build: ## Собрать бинарник tplater в bin/.
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .
	@echo "built $(BIN) (version=$(VERSION))"

clean: ## Удалить артефакты сборки.
	rm -rf bin

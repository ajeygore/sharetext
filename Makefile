# ShareText — one-time encrypted text sharing.
#
# Tailwind is a build-time tool only: the stylesheet it produces is committed
# and embedded in the binary, so deploying needs neither Node nor Tailwind.

TAILWIND_VERSION := v4.1.11
BIN              := bin/tailwindcss
REDIS_ADDR       ?= 127.0.0.1:6380

.DEFAULT_GOAL := help

.PHONY: help dev build css test test-go test-js run fmt vet clean tailwind

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: css ## Build the server binary
	go build -o bin/sharetext ./cmd/server

css: $(BIN) ## Rebuild the stylesheet
	$(BIN) -i tailwind.input.css -o web/static/css/app.css --minify

tailwind: $(BIN) ## Fetch the pinned Tailwind CLI

$(BIN):
	@mkdir -p bin
	@case "$$(uname -s)-$$(uname -m)" in \
	  Darwin-arm64)  A=tailwindcss-macos-arm64 ;; \
	  Darwin-x86_64) A=tailwindcss-macos-x64 ;; \
	  Linux-aarch64) A=tailwindcss-linux-arm64 ;; \
	  *)             A=tailwindcss-linux-x64 ;; \
	esac; \
	curl -sSL -o $(BIN) "https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/$$A"
	@chmod +x $(BIN)

test: test-go test-js ## Run every test

test-go: ## Go tests (needs Redis: docker compose up -d)
	REDIS_ADDR=$(REDIS_ADDR) go test ./...

# The browser crypto is the one thing that cannot be Go, so it is the one thing
# tested with node. Zero dependencies: node:test plus the WebCrypto globals.
test-js: ## Browser crypto tests
	node --test test/crypto.test.mjs

run: build ## Build and run
	./bin/sharetext

dev: css ## Run from source
	go run ./cmd/server

fmt: ## Format
	gofmt -w ./cmd ./internal ./web

vet: ## Vet
	go vet ./...

clean: ## Remove build output
	rm -rf bin/sharetext

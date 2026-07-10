# flareover: common tasks. `make help` lists them.
BIN := flareover

.PHONY: help build test race vet lint fmt cover run clean
help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

build: ## Build the CLI
	go build -o $(BIN) ./cmd/flareover

test: ## Run tests
	go test ./...

race: ## Run tests with the race detector (what CI runs)
	go test -race ./...

vet: ## go vet
	go vet ./...

lint: ## staticcheck (install if missing)
	@command -v staticcheck >/dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

fmt: ## Format
	gofmt -w ./cmd ./internal

cover: ## Coverage summary
	go test -cover ./...

clean: ## Remove build artifacts
	rm -f $(BIN)
	rm -rf dist

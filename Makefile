# Variables
BINARY_FOLDER = build
BINARY_NAME = intents-cli

# Build the Go binary
build:
	@echo "Building" $(BINARY_NAME) "in the" $(BINARY_FOLDER) "folder..."
	@go build -o $(BINARY_FOLDER)/$(BINARY_NAME)

# Lint the Go code
lint:
	@echo "Linting the Go code..."
	@golangci-lint run

## TESTS
TEST_PACKAGES=$(shell go list ./...)
TEST_TARGETS := test-unit test-race
BASE_FLAGS=-mod=readonly -timeout=5m
test-unit: ARGS=-tags=norace
test-race: ARGS=-race
$(TEST_TARGETS): run-tests

run-tests:
	@echo "--> Running tests $(BASE_FLAGS) $(ARGS)"
ifneq (,$(shell which tparse 2>/dev/null))
	@go test $(BASE_FLAGS) -json $(ARGS) $(TEST_PACKAGES) | tparse
else
	@go test $(BASE_FLAGS) $(ARGS) $(TEST_PACKAGES)
endif

# Clean up
clean:
	@echo "Cleaning up..."
	@rm $(BINARY_NAME)

.PHONY: run build lint clean

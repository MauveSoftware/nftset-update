BINARY  := nftset-update
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test test-integration lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o $(BINARY) .

test:
	go test ./...

# Runs the kernel tests in a private user + network namespace; the host
# ruleset is never touched.
test-integration:
	go test -c -tags integration -o nftset.integration.test ./internal/nftset
	unshare -rn ./nftset.integration.test -test.v -test.timeout 10m
	rm -f nftset.integration.test

lint:
	go vet ./...
	go vet -tags integration ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed, skipped"; fi

clean:
	rm -f $(BINARY) nftset.integration.test

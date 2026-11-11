BINARY_NAME = nfgtfa
PKG = ./cmd/aggregator

.PHONY: all build test lint docker-test clean

all: test build

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY_NAME) $(PKG)

test:
	go vet ./...
	go test -race ./...

lint:
	golangci-lint run ./...

# Needs a running docker daemon; pulls linuxserver/syslog-ng.
docker-test:
	go test -tags docker -run Integration -v ./internal/reconcile/

clean:
	rm -f $(BINARY_NAME)

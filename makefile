BINARY_NAME = nfgtfa
PKG = ./cmd/aggregator

.PHONY: all build test lint docker-test e2e clean

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

# Needs Docker on Linux; removes nfg-* containers and tpotce_nginx_local.
# Set NFGTFA_V1_BINARY to a 1.x binary to include the upgrade test.
e2e:
	go test -tags e2e -count=1 -timeout 20m -v ./e2e/

clean:
	rm -f $(BINARY_NAME)

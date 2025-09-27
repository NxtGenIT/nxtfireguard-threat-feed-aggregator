BINARY_NAME = nfgtfa
PKG = ./cmd/aggregator

.PHONY: all build clean static musl

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) $(PKG)

static:
	@echo "Building statically linked $(BINARY_NAME)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME) $(PKG)

musl:
	@echo "Building musl-linked static binary..."
	CGO_ENABLED=1 CC=musl-gcc GOOS=linux GOARCH=amd64 \
	go build -ldflags="-linkmode external -extldflags '-static' -s -w" -o $(BINARY_NAME) $(PKG)

clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
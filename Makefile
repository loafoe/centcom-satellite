.PHONY: build test lint clean ko-build ko-push deploy run verify

BINARY_NAME=centcom-satellite
IMAGE_NAME=ghcr.io/loafoe/centcom-satellite
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/centcom-satellite

test:
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out coverage.html

run:
	go run ./cmd/centcom-satellite

# Build image locally with ko (for testing)
ko-build:
	KO_DOCKER_REPO=$(IMAGE_NAME) VERSION=$(VERSION) ko build ./cmd/centcom-satellite --bare --local --tags=$(VERSION)

# Build and push image with ko
ko-push:
	KO_DOCKER_REPO=$(IMAGE_NAME) VERSION=$(VERSION) ko build ./cmd/centcom-satellite --bare --platform=linux/amd64,linux/arm64 --tags=$(VERSION),latest

# Sign image with cosign (requires COSIGN_PASSWORD or keyless)
sign:
	cosign sign --yes $(IMAGE_NAME):$(VERSION)

# Verify image signature
verify:
	cosign verify $(IMAGE_NAME):$(VERSION) \
		--certificate-identity-regexp="https://github.com/loafoe/centcom-satellite/*" \
		--certificate-oidc-issuer="https://token.actions.githubusercontent.com"

deploy:
	kubectl apply -k deploy/

mod-tidy:
	go mod tidy

fmt:
	go fmt ./...

vet:
	go vet ./...

all: fmt vet lint test build

.DEFAULT_GOAL := build

BIN_DIR ?= bin
VERSION ?= dev

.PHONY: build vet test test-integration sast

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o "$(BIN_DIR)/kube-vpn" ./cmd/kube-vpn

vet:
	go vet ./...

test:
	go test -v -race -cover ./...

test-integration:
	go test -tags=integration -v -timeout 5m ./test/integration/...

sast:
	./scripts/sast.sh

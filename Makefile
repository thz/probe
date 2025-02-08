.PHONY: default
default: lint test

.PHONY: test
test:
	nice go build -o probe ./cmd
	./probe probe google.com:443

.PHONY: all
all: probe probe-linux-amd64 probe-linux-arm64

sources = $(shell find . -name '*.go')
probe: $(sources)
	go build -o $@ ./cmd

probe-linux-amd64:
	GOARCH=amd64 GOOS=linux go build -o $@ ./cmd

probe-linux-arm64:
	GOARCH=arm64 GOOS=linux go build -o $@ ./cmd

.PHONY: lint
lint:
	docker run --rm -v $(shell pwd):/app \
		-v ~/.cache/golangci-lint/v1.62.0:/root/.cache \
		-w /app golangci/golangci-lint:v1.62.0 \
		golangci-lint run -v

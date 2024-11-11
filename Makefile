
.PHONY: test
test:
	nice go build -o probe ./cmd
	./probe probe google.com:443

.PHONY: all
all: probe probe-linux-amd64 probe-linux-arm64

probe:
	go build -o $@ ./cmd

probe-linux-amd64:
	GOARCH=amd64 GOOS=linux go build -o $@ ./cmd

probe-linux-arm64:
	GOARCH=arm64 GOOS=linux go build -o $@ ./cmd

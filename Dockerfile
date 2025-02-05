FROM golang:1.23-bookworm AS build-stage

LABEL org.opencontainers.image.source="https://github.com/thz/probe"
LABEL org.opencontainers.image.description="thz/probe a DNS,TCP,TLS prober"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -qq -y libpcap-dev

ADD . /go/src/github.com/thz/probe
WORKDIR /go/src/github.com/thz/probe

RUN env CGO_ENABLED=1 go build -o probe ./cmd

FROM debian:bookworm-slim AS run-stage


# make the container slightly more useful for diagostics
RUN apt-get update && apt-get install -qq -y \
	inetutils-telnet \
	iproute2 \
	iptables \
	iputils-ping \
	ldnsutils \
	openssl \
	socat \
	tcpdump

COPY --from=build-stage /go/src/github.com/thz/probe/probe /usr/bin/probe

ENTRYPOINT [ "/usr/bin/probe" ]

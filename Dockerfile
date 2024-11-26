FROM golang:1.23-bookworm AS build-stage

ADD . /go/src/github.com/thz/probe
WORKDIR /go/src/github.com/thz/probe
RUN env CGO_ENABLED=1 go build -o probe ./cmd

FROM debian:bookworm-slim AS run-stage

LABEL org.opencontainers.image.source=https://github.com/thz/probe

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

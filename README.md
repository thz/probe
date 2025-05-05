# thz/probe -- Probe TCP/TLS endpoints

## What is this?

 - a tool to diagnose TCP/TLS connections
 - a tool to probe TCP/TLS endpoints (`probe probe`)
 - a tool to observe incoming TCP/TLS connections (`probe capture`)

Next to DNS and certificate details, SNI headers and proxy protocol headers (v1 and v2) are verbosley sent and received.

## Why this tool?

To diagnose a failing TLS connection to foo.example.com:12345, I used to:

 - check DNS resolving
 - check TCP establishment
 - check TLS handshake / certificates

I prefered `drill` (similar to `dig`) to check DNS resolving, `telnet` to check TCP establishment and `openssl s_client` to check TLS establishment and certificates.

To smoothen the process, I wrote `thz/probe` to do all these checks in one go and provide exactly the relevant details for every step.

## How to Get/Install it

Download the latest binary from the GitHub release page: https://github.com/thz/probe/releases/latest

Alternatively, you can:
```
# build it yourself (without cloning)
GOBIN=$(pwd) go install github.com/thz/probe/cmd/probe@latest
./probe google.com:443

# build it yourself
git clone https://github.com/thz/probe
cd probe
make probe test

# use docker
docker pull thzpub/probe # optional
docker run --rm -ti thzpub/probe google.com:443
```

## Probe Usage

```
% ./probe probe foo.example.com:12345
RESOLVE/A 192.0.2.100
TCP/ESTABLISHED 192.0.2.100:12345
TLS/ESTABLISHED peer-subject: CN=*.example.com
```

Use of the docker container is very similar:
```
% docker run --rm -ti thzpub/probe probe google.com:443
```

You might want to consider adding `--network host` to the `docker run` command to avoid additional network overhead (NAT) from the container network namespace.

In addition to that, it should also be usable as a library to be integrated into other tools.

### Explicit ServerName (SNI header)

```
% ./probe probe --sni foo.example.com example.com:12345
```

This will use `foo.example.com` as server name indication (SNI) header during the TLS handshake (ClientHello).

### Proxy Protocol Support

```
% ./probe probe --proxy-protocol-v1 foo.example.com:12345
% ./probe probe --proxy-protocol-v2 foo.example.com:12345
```

This will send a PROXY protocol header after successful TCP connection establishment. See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt for details.


## Capture Usage

The capture command will listen on a network interface and print details about observed TCP connections. It is not a general purpose packet sniffer, but rather a tool to show specific details about TCP/TLS connections (SNI header, proxy protocol header, TLS certificate peer).
The flag `--iface` is used to specify the network interface to listen on. The flag `--bpf` can be used to filter the to-be-observed packets.

### Example: A Regular HTTPS Request

The `capture` subcommand can be used to observe the actual TLS server name (SNI HEADER) used during the TLS handshake:

```
% curl https://github.com

# capture command:
% ./probe capture --iface eth0 --bpf "dst port 443"
TLS_CLIENT_HELLO FlowID='192.168.178.26:42942 -> 140.82.121.4:443' TLSServerName='github.com'
```

### Example: Probe with Explicit SNI Header

The `--sni` flag of the `probe` subcommand allows specification of the TLS server name (SNI HEADER), which may differ from the hostname used to establish the TCP connection:

```
% probe --sni probing.example.com 1.1.1.1:443
RESOLVE/IP-LITERAL 1.1.1.1
TCP/ESTABLISHED local=192.168.178.26:45930 peer=1.1.1.1:443
TLS/CERTIFICATE peer-subject=CN=cloudflare-dns.com,O=Cloudflare\, Inc.,L=San Francisco,ST=California,C=US
TLS/ESTABLISHED tls-version=TLS1.3

# capture command:
% ./probe capture --iface eth0 --bpf "dst port 443"
TLS_CLIENT_HELLO FlowID='192.168.178.26:45930 -> 1.1.1.1:443' TLSServerName='probing.example.com'
```

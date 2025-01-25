# thz/probe -- Probe TCP/TLS endpoints

## Why this tool?

To diagnose a failing TLS connection to foo.example.com:12345, I used to:

 - check DNS resolving
 - check TCP establishment
 - check TLS handshake / certificates

I prefered `drill` (similar to `dig`) to check DNS resolving, `telnet` to check TCP establishment and `openssl s_client` to check TLS establishment and certificates.

To smoothen the process, I wrote `thz/probe` to do all these checks in one go and provide exactly the relevant details for every step.

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

The capture command will listen on a network interface and print details about observed TCP connections.

```
% ./probe capture --iface eth0 --bpf "dst port 443"
```

# thz/probe -- Probe TCP/TLS endpoints

## Why is the TLS connection to foo.example.com:12345 failing?

I used to:

 - check DNS resolving
 - check TCP establishment
 - check TLS handshake / certificates

I prefered `drill` (similar to `dig`) to check DNS resolving, `telnet` to check TCP establishment and `openssl s_client` to check TLS establishment and certificates.

To smoothen the process, I wrote `thz/probe` to do all these checks in one go and provide exactly the relevant details for every step.

```
% ./probe probe foo.example.com:12345
RESOLVE/A 192.0.2.100
TCP/ESTABLISHED 192.0.2.100:12345
TLS/ESTABLISHED peer-subject: CN=*.example.com
```

Use of the docker container is very similar:
```
% docker run --rm -ti thz/probe probe google.com:443
```

You might want to consider adding `--network host` to the `docker run` command to avoid additional network overhead (NAT) from the container network namespace.


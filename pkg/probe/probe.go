// Copyright 2020 Tobias Hintze
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/paraopsde/go-x/pkg/util"
	proxyproto "github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

type ProxyProtocolMode string

const (
	ProxyProtocolDisabled ProxyProtocolMode = ""
	ProxyProtocolV1       ProxyProtocolMode = "v1"
	ProxyProtocolV2       ProxyProtocolMode = "v2"
)

type ProbeOptions struct {
	Endpoint             string
	ProxyProtocolMode    ProxyProtocolMode
	ServerNameIndication string
}

type Signal struct {
	Path    string
	Message string
	Error   error
}

type prober struct {
	endpoint          string
	fqdn              string
	port              string
	addresses         []net.IP
	conn              net.Conn
	tlsConn           *tls.Conn
	proxyProtocolMode ProxyProtocolMode
	sni               string
}

func NewProber(o ProbeOptions) (*prober, error) {
	p := &prober{
		endpoint:          o.Endpoint,
		proxyProtocolMode: o.ProxyProtocolMode,
		sni:               o.ServerNameIndication,
	}
	parts := strings.Split(p.endpoint, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid endpoint '%s'", p.endpoint)
	}
	p.fqdn = parts[0]
	p.port = parts[1]

	if p.sni == "" {
		p.sni = p.fqdn
	}
	return p, nil
}

func (p *prober) Probe(ctx context.Context) error {
	log := util.CtxLogOrPanic(ctx)
	defer log.Sync()
	signals := make(chan Signal)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func(ctx context.Context, signals chan Signal) {
		defer wg.Done()
		for signal := range signals {
			if signal.Error != nil {
				fmt.Printf("%s FAILED: %v\n", signal.Path, signal.Error)
			} else {
				fmt.Printf("%s %s\n", signal.Path, signal.Message)
			}
		}
	}(ctx, signals)

	err := p.probe(ctx, signals)
	if err != nil {
		log.Info("probe failed", zap.Error(err))
		fmt.Printf("Probe failed: %v\n", err)
		return nil // we are swallowing the error here
	}
	wg.Wait()
	return nil
}

func (p *prober) probe(ctx context.Context, signals chan Signal) error {
	log := util.CtxLogOrPanic(ctx).
		With(zap.String("fqdn", p.fqdn)).
		With(zap.String("port", p.port))

	log.Info("probing")

	// DNS
	p.resolve(ctx, signals)

	// TCP - connect to first address only
	p.connectTcp(ctx, signals, 0)

	p.maybeSendProxyProtocolHeaders(ctx, signals)

	// TLS - upgrade to tls
	p.upgradeTls(ctx, signals)

	close(signals)

	return nil
}

func (p *prober) sendProxyProtocolV2Headers(ctx context.Context,
	localIp, remoteIp, localPortStr, remotePortStr string,
) error {
	log := util.CtxLogOrPanic(ctx)

	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		return fmt.Errorf("failed to convert local port to int: %w", err)
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return fmt.Errorf("failed to convert remote port to int: %w", err)
	}

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(localIp),
			Port: localPort,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP(remoteIp),
			Port: remotePort,
		},
	}

	log.Info("sending proxy protocol v2 headers", zap.Any("header", header))
	_, err = header.WriteTo(p.conn)
	if err != nil {
		return fmt.Errorf("failed to write proxy protocol v2 headers: %w", err)
	}
	fmt.Printf("PROXY protocol v2 headers sent.\n")
	return nil
}

func (p *prober) maybeSendProxyProtocolHeaders(ctx context.Context, signals chan Signal) {
	log := util.CtxLogOrPanic(ctx)

	if p.proxyProtocolMode == "" {
		return
	}

	if p.conn == nil {
		log.Info("no tcp connection, skipping proxy protocol headers")
		return
	}

	local := p.conn.LocalAddr().String()
	localIp, localPort, err := net.SplitHostPort(local)
	if err != nil {
		signals <- Signal{Path: "PROXYPROTOCOL/ERROR", Error: fmt.Errorf("failed to split local address: %w", err)}
		return
	}

	remote := p.conn.RemoteAddr().String()
	remoteIp, remotePort, err := net.SplitHostPort(remote)
	if err != nil {
		signals <- Signal{Path: "PROXYPROTOCOL/ERROR", Error: fmt.Errorf("failed to split remote address: %w", err)}
		return
	}

	if p.proxyProtocolMode == "v2" {
		if err := p.sendProxyProtocolV2Headers(ctx, localIp, remoteIp, localPort, remotePort); err != nil {
			signals <- Signal{Path: "PROXYPROTOCOL/V2/ERROR", Error: err}
		} else {
			signals <- Signal{Path: "PROXYPROTOCOL/V2/SENT", Message: fmt.Sprintf("local: %s:%s, remote: %s:%s", localIp, localPort, remoteIp, remotePort)}
		}
		return
	}

	ppHeader := fmt.Sprintf("PROXY TCP4 %s %s %s %s\r\n",
		localIp, remoteIp, localPort, remotePort)
	log.Info("sending proxy protocol headers", zap.String("ppheader", ppHeader))
	n, err := p.conn.Write([]byte(ppHeader))
	if n != len(ppHeader) {
		signals <- Signal{Path: "PROXYPROTOCOL/V1/ERROR", Error: fmt.Errorf("failed to write proxy protocol headers: length mismatch")}
		return
	}
	if err != nil {
		signals <- Signal{Path: "PROXYPROTOCOL/V1/ERROR", Error: fmt.Errorf("failed to write proxy protocol headers: %w", err)}
		return
	}
	signals <- Signal{Path: "PROXYPROTOCOL/V1/SENT", Message: strings.TrimSpace(ppHeader)}
}

func (p *prober) upgradeTls(ctx context.Context, signals chan Signal) {
	log := util.CtxLogOrPanic(ctx)

	if p.conn == nil {
		log.Info("no tcp connection, skipping upgrade to tls")
		return
	}

	log.Info("upgrading to tls")
	p.tlsConn = tls.Client(p.conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         p.sni,
	})

	if err := p.tlsConn.HandshakeContext(ctx); err != nil {
		signals <- Signal{Path: "TLS/ERROR", Error: fmt.Errorf("failed to handshake: %w", err)}
		return
	}

	tlsState := p.tlsConn.ConnectionState()
	signals <- Signal{Path: "TLS/ESTABLISHED", Message: "peer-subject: " + tlsState.PeerCertificates[0].Subject.String()}
}

func (p *prober) connectTcp(ctx context.Context, signals chan Signal, index int) {
	// `index` evaluation and controlling which address to use is not implemented yet
	var err error
	log := util.CtxLogOrPanic(ctx)
	if len(p.addresses) <= index {
		log.Info("no addresses resolved, skipping tcp connect")
		return
	}
	dst := p.addresses[index]
	log = log.With(zap.Any("dst", dst))

	log.Info("dialing tcp")
	dialer := &net.Dialer{}
	p.conn, err = dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", dst, p.port))
	if err != nil {
		signals <- Signal{Path: "TCP/ERROR", Error: fmt.Errorf("failed to dial tcp: %w", err)}
		return
	}

	signals <- Signal{Path: "TCP/ESTABLISHED", Message: fmt.Sprintf("%s:%s", dst, p.port)}
}

func (p *prober) resolve(ctx context.Context, signals chan Signal) {
	log := util.CtxLogOrPanic(ctx).
		With(zap.String("fqdn", p.fqdn))

	// check if fqdn is an IP address
	if ip := net.ParseIP(p.fqdn); ip != nil {
		signals <- Signal{Path: "RESOLVE/IP-LITERAL", Message: ip.String()}
		p.addresses = []net.IP{ip}
		return
	}

	log.Info("resolving")

	resolver := net.DefaultResolver
	name := p.fqdn
	for {
		cname, err := resolver.LookupCNAME(ctx, name)
		if err != nil {
			signals <- Signal{Path: "RESOLVE/A/ERROR", Error: err}
			return
		}
		if cname == "" {
			signals <- Signal{Path: "RESOLVE/A/ERROR", Error: fmt.Errorf("empty cname from '%s'", name)}
			return
		}
		if cname == name || cname == name+"." {
			// no more CNAMEs
			break
		}

		signals <- Signal{Path: "RESOLVE/CNAME", Message: fmt.Sprintf("%s -> %s", name, cname)}
		name = cname
	}

	log.Info("resolving IP from name", zap.String("name", name))
	ips, err := resolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		signals <- Signal{
			Path:  "RESOLVE/A/ERROR",
			Error: fmt.Errorf("failed to resolve IP for '%s': %w", name, err),
		}
		return
	}

	for _, ip := range ips {
		signals <- Signal{Path: "RESOLVE/A", Message: ip.String()}
	}

	p.addresses = ips
}

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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
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
	var err error
	p.fqdn, p.port, err = net.SplitHostPort(p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint '%s'", p.endpoint)
	}

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

func (p *prober) sendProxyProtocolHeaders(ctx context.Context,
	ppMode ProxyProtocolMode,
	localIp, remoteIp, localPortStr, remotePortStr string,
) error {
	if ppMode == ProxyProtocolDisabled {
		return fmt.Errorf("proxy protocol is disabled")
	}

	log := util.CtxLogOrPanic(ctx).With(
		zap.String("ppVersion", string(ppMode)),
	)

	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		return fmt.Errorf("failed to convert local port to int: %w", err)
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return fmt.Errorf("failed to convert remote port to int: %w", err)
	}

	header := &proxyproto.Header{
		Version:           1,
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

	if ppMode == ProxyProtocolV2 {
		header.Version = 2
	}
	log = log.With(zap.Any("header", header))

	// serialize the header
	ppBytes, errFormat := header.Format()
	if errFormat != nil {
		return fmt.Errorf("failed to serialize proxy protocol %s header: %w", ppMode, errFormat)
	}

	// ppv1 is human readable
	if ppMode == ProxyProtocolV1 {
		log = log.With(zap.String("raw-v1-header", string(ppBytes)))
	}

	log.Info("sending proxy protocol headers")
	_, err = bytes.NewBuffer(ppBytes).WriteTo(p.conn)
	if err != nil {
		return fmt.Errorf("failed to write proxy protocol %s headers: %w", ppMode, err)
	}
	log.Info("sent proxy protocol headers")
	return nil
}

func (p *prober) maybeSendProxyProtocolHeaders(ctx context.Context, signals chan Signal) {
	log := util.CtxLogOrPanic(ctx)

	if p.proxyProtocolMode == ProxyProtocolDisabled {
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

	if ppErr := p.sendProxyProtocolHeaders(ctx, p.proxyProtocolMode, localIp, remoteIp, localPort, remotePort); ppErr != nil {
		signals <- Signal{Path: "PROXYPROTOCOL/ERROR", Error: ppErr}
		return
	}
	signals <- Signal{
		Path:    "PROXYPROTOCOL/SENT",
		Message: fmt.Sprintf("version: %s, local: %s, remote: %s", p.proxyProtocolMode, local, remote),
	}
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

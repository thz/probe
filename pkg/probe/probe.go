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
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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

	LocalAddress      net.Addr
	PeerAddress       net.Addr
	PeerSubject       string
	SANs              []string
	ValidityNotBefore time.Time
	ValidityNotAfter  time.Time
	TLSVersion        string
}

var errTLSFailure = fmt.Errorf("TLS failure")

func (s Signal) String() string {
	parts := []string{s.Path}
	if s.Error != nil {
		parts = append(parts, "ERROR=\""+s.Error.Error()+"\"")
	}

	if s.Message != "" {
		parts = append(parts, s.Message)
	}

	if s.LocalAddress != nil {
		parts = append(parts, "local="+s.LocalAddress.String())
	}
	if s.PeerAddress != nil {
		parts = append(parts, "peer="+strings.TrimSuffix(s.PeerAddress.String(), ":0"))
	}

	if s.PeerSubject != "" {
		parts = append(parts, "peer-subject="+s.PeerSubject)
	}
	if len(s.SANs) > 0 {
		parts = append(parts, "SANs="+strings.Join(s.SANs, ","))
	}

	if !s.ValidityNotBefore.IsZero() {
		parts = append(parts, "validity-not-before="+s.ValidityNotBefore.Format(time.RFC3339))
	}
	if !s.ValidityNotAfter.IsZero() {
		parts = append(parts, "validity-not-after="+s.ValidityNotAfter.Format(time.RFC3339))
	}

	if s.TLSVersion != "" {
		parts = append(parts, "tls-version="+strings.ReplaceAll(s.TLSVersion, " ", ""))
	}
	return strings.Join(parts, " ")
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
	signals           chan Signal
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
		return nil, fmt.Errorf("%w: bad endpoint syntax in '%s'",
			ErrInvalidArgument, p.endpoint)
	}

	if p.sni == "" {
		p.sni = p.fqdn
	}
	return p, nil
}

func (p *prober) Probe(ctx context.Context) error {
	log := util.CtxLogOrPanic(ctx)
	defer log.Sync()
	p.signals = make(chan Signal)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func(ctx context.Context, signals chan Signal) {
		defer wg.Done()
		for signal := range signals {
			if signal.Error != nil {
				fmt.Printf("%s FAILED: %v\n", signal.Path, signal.Error)
			} else {
				fmt.Printf("%s\n", signal)
			}
		}
	}(ctx, p.signals)

	err := p.probe(ctx)
	if err != nil {
		log.Info("probe failed", zap.Error(err))
		fmt.Printf("Probe failed: %v\n", err)
		return nil // we are swallowing the error here
	}
	wg.Wait()
	return nil
}

func (p *prober) probe(ctx context.Context) error {
	log := util.CtxLogOrPanic(ctx).
		With(zap.String("fqdn", p.fqdn)).
		With(zap.String("port", p.port))

	log.Info("probing")

	// DNS
	p.resolve(ctx)

	// TCP - connect to first address only
	p.connectTcp(ctx, 0)

	p.maybeSendProxyProtocolHeaders(ctx)

	// TLS - upgrade to tls
	p.upgradeTls(ctx)

	close(p.signals)

	return nil
}

func (p *prober) sendProxyProtocolHeaders(ctx context.Context,
	ppMode ProxyProtocolMode,
	localIp, remoteIp, localPortStr, remotePortStr string,
) error {
	if ppMode == ProxyProtocolDisabled {
		return ErrProxyProtocolDisabled
	}

	log := util.CtxLogOrPanic(ctx).With(
		zap.String("ppVersion", string(ppMode)),
	)

	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		return fmt.Errorf("%w: invalid local port", ErrInvalidArgument)
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return fmt.Errorf("%w: invalid remote port", ErrInvalidArgument)
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
		return fmt.Errorf("%w: failed to serialize %s header: %s", ErrProxyProtocol, ppMode, errFormat.Error())
	}

	// ppv1 is human readable
	if ppMode == ProxyProtocolV1 {
		log = log.With(zap.String("raw-v1-header", string(ppBytes)))
	}

	log.Info("sending proxy protocol headers")
	_, err = bytes.NewBuffer(ppBytes).WriteTo(p.conn)
	if err != nil {
		return fmt.Errorf("%w: failed to write proxy protocol %s headers: %s",
			ErrProxyProtocol, ppMode, err.Error())
	}
	log.Info("sent proxy protocol headers")
	return nil
}

func (p *prober) maybeSendProxyProtocolHeaders(ctx context.Context) {
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
		p.signals <- Signal{
			Path:  "PROXYPROTOCOL/ERROR",
			Error: fmt.Errorf("%w: cannot parse local address '%s'", ErrInvalidArgument, local),
		}
		return
	}

	remote := p.conn.RemoteAddr().String()
	remoteIp, remotePort, err := net.SplitHostPort(remote)
	if err != nil {
		p.signals <- Signal{
			Path:  "PROXYPROTOCOL/ERROR",
			Error: fmt.Errorf("%w: cannot parse remote address '%s'", ErrInvalidArgument, remote),
		}
		return
	}

	if ppErr := p.sendProxyProtocolHeaders(ctx, p.proxyProtocolMode, localIp, remoteIp, localPort, remotePort); ppErr != nil {
		p.signals <- Signal{Path: "PROXYPROTOCOL/ERROR", Error: ppErr}
		return
	}
	p.signals <- Signal{
		Path:    "PROXYPROTOCOL/SENT",
		Message: fmt.Sprintf("version: %s, local: %s, remote: %s", p.proxyProtocolMode, local, remote),
	}
}

func (p *prober) upgradeTls(ctx context.Context) {
	log := util.CtxLogOrPanic(ctx)

	if p.conn == nil {
		log.Info("no tcp connection, skipping upgrade to tls")
		return
	}

	log.Info("upgrading to tls", zap.String("sni-header", p.sni))
	p.tlsConn = tls.Client(p.conn, &tls.Config{
		InsecureSkipVerify:    true, //nolint:gosec
		ServerName:            p.sni,
		VerifyPeerCertificate: p.verifyCerts,
	})

	if err := p.tlsConn.HandshakeContext(ctx); err != nil {
		p.signals <- Signal{
			Path:  "TLS/ERROR",
			Error: fmt.Errorf("%w: TLS handshake failed: %s", ErrProtocolViolation, err.Error()),
		}
		return
	}

	tlsState := p.tlsConn.ConnectionState()
	p.signals <- Signal{
		Path:       "TLS/ESTABLISHED",
		TLSVersion: tls.VersionName(tlsState.Version),
	}
}

func (p *prober) connectTcp(ctx context.Context, index int) {
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
		p.signals <- Signal{
			Path:  "TCP/ERROR",
			Error: fmt.Errorf("%w: failed to connect: %s", ErrTCP, err.Error()),
		}
		return
	}

	p.signals <- Signal{
		Path:         "TCP/ESTABLISHED",
		PeerAddress:  p.conn.RemoteAddr(),
		LocalAddress: p.conn.LocalAddr(),
	}
}

func (p *prober) resolve(ctx context.Context) {
	log := util.CtxLogOrPanic(ctx).
		With(zap.String("fqdn", p.fqdn))

	// check if fqdn is an IP address
	if ip := net.ParseIP(p.fqdn); ip != nil {
		p.signals <- Signal{Path: "RESOLVE/IP-LITERAL", Message: ip.String()}
		p.addresses = []net.IP{ip}
		return
	}

	log.Info("resolving")

	resolver := net.DefaultResolver
	name := p.fqdn
	for {
		cname, err := resolver.LookupCNAME(ctx, name)
		if err != nil {
			p.signals <- Signal{Path: "RESOLVE/A/ERROR", Error: err}
			return
		}
		if cname == "" {
			p.signals <- Signal{
				Path:  "RESOLVE/A/ERROR",
				Error: fmt.Errorf("%w: empty cname from '%s'", ErrUnexpectedResponse, name),
			}
			return
		}
		if cname == name || cname == name+"." {
			// no more CNAMEs
			break
		}

		p.signals <- Signal{Path: "RESOLVE/CNAME", Message: fmt.Sprintf("%s -> %s", name, cname)}
		name = cname
	}

	log.Info("resolving IP from name", zap.String("name", name))
	ips, err := resolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		p.signals <- Signal{
			Path:  "RESOLVE/A/ERROR",
			Error: fmt.Errorf("%w: failed to resolve IP for '%s': %s", ErrResolve, name, err.Error()),
		}
		return
	}

	for _, ip := range ips {
		p.signals <- Signal{
			Path:        "RESOLVE/A",
			PeerAddress: net.Addr(&net.TCPAddr{IP: ip}),
		}
	}

	p.addresses = ips
}

func (p *prober) verifyCerts(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// get certificate details from raw certs
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: no certificates", errTLSFailure)
	}

	// first one is the subject, remainder is the chain
	rawCert := rawCerts[0]
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	p.signals <- Signal{
		Path:              "TLS/CERTIFICATE",
		ValidityNotAfter:  cert.NotAfter,
		ValidityNotBefore: cert.NotBefore,
		SANs:              sansFromCert(cert),
		PeerSubject:       cert.Subject.String(),
	}
	return nil
}

func sansFromCert(cert *x509.Certificate) []string {
	SANs := []string{}
	SANs = append(SANs, cert.DNSNames...)
	SANs = append(SANs, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		SANs = append(SANs, ip.String())
	}
	for _, uri := range cert.URIs {
		SANs = append(SANs, uri.String())
	}
	return SANs
}

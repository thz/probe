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

package capture

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	proxyproto "github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

var proxyProtocolVersions = map[byte]string{1: "v1", 2: "v2"}

type CaptureType string

const (
	CaptureTypePcap     CaptureType = "pcap"
	CaptureTypePcapFile CaptureType = "pcap-file"
	CaptureTypeAfpacket CaptureType = "afpacket"
)

type SignalType int

const (
	SignalTypeProxyProtocolHeader SignalType = iota
	SignalTypeTLSClientHello      SignalType = iota
	SignalTypeError               SignalType = iota
)

func (st SignalType) String() string {
	switch st {
	case SignalTypeProxyProtocolHeader:
		return "PROXY_PROTOCOL_HEADER"
	case SignalTypeTLSClientHello:
		return "TLS_CLIENT_HELLO"
	case SignalTypeError:
		return "ERROR"
	}
	return "UNKNOWN"
}

type Signal struct {
	Type   SignalType
	Error  error
	FlowID string

	TLSServerName string

	PPSourceAddr      net.Addr
	PPDestinationAddr net.Addr
	PPVersion         string
}

func (s Signal) String() string {
	if s.Error != nil {
		return fmt.Sprintf("%s FAILED: %v", s.Type, s.Error)
	}
	details := []string{s.Type.String()}
	if s.FlowID != "" {
		details = append(details, fmt.Sprintf("FlowID='%s'", s.FlowID))
	}
	if s.TLSServerName != "" {
		details = append(details, fmt.Sprintf("TLSServerName='%s'", s.TLSServerName))
	}
	if s.PPSourceAddr != nil {
		details = append(details, fmt.Sprintf("PPSourceAddr='%s'", s.PPSourceAddr.String()))
	}
	if s.PPDestinationAddr != nil {
		details = append(details, fmt.Sprintf("PPDestinationAddr='%s'", s.PPDestinationAddr.String()))
	}
	if s.PPVersion != "" {
		details = append(details, fmt.Sprintf("PPVersion='%s'", s.PPVersion))
	}
	if s.Error != nil {
		details = append(details, fmt.Sprintf("Error='%s'", s.Error.Error()))
	}

	return strings.Join(details, " ")
}

type SNICapturer struct {
	ifaceName    string
	bpfFilter    string
	packetSource *gopacket.PacketSource
	captureType  CaptureType

	output chan Signal
}

type streamFactory struct {
	log          *zap.Logger
	streamsMutex sync.Mutex
	streams      map[string]*stream
	ctx          context.Context
	signals      chan Signal
}
type stream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	log            *zap.Logger
	id             string
}

func newStreamFactory(ctx context.Context, log *zap.Logger, signals chan Signal) *streamFactory {
	return &streamFactory{
		log:     log,
		streams: make(map[string]*stream),
		ctx:     ctx,
		signals: signals,
	}
}

func streamKey(net, transport gopacket.Flow) string {
	return fmt.Sprintf("%s:%s -> %s:%s", net.Src().String(), transport.Src().String(),
		net.Dst().String(), transport.Dst().String())
}

func (sf *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	streamId := streamKey(net, transport)

	s := &stream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		log:       sf.log.With(zap.String("stream-id", streamId)),
		id:        streamId,
	}

	sf.streamsMutex.Lock()
	if _, ok := sf.streams[streamId]; ok {
		sf.log.Warn("stream already exists", zap.String("stream-id", streamId))
	}
	sf.streams[streamId] = s
	streamCount := len(sf.streams)
	sf.streamsMutex.Unlock()
	s.log.Info("new stream", zap.Int("stream-count", streamCount))
	go func() {
		s.run(sf.ctx, sf.signals)
		sf.streamsMutex.Lock()
		delete(sf.streams, streamId)
		streamCount = len(sf.streams)
		sf.streamsMutex.Unlock()
		sf.log.Info("stream removed", zap.Int("count", streamCount), zap.String("stream-id", streamId))
	}()
	return &s.r
}

func (s *stream) run(ctx context.Context, signals chan Signal) {
	if s.log == nil {
		panic("log is nil")
	}
	log := s.log
	defer log.Sync()

	buf := bufio.NewReaderSize(&s.r, 2048)
	defer drainReader(buf)

	ppHeader, errPp := proxyproto.Read(buf)
	if errPp != nil && !errors.Is(errPp, proxyproto.ErrNoProxyProtocol) {
		log.Info("failed to read PROXY header", zap.Error(errPp))
		signals <- Signal{
			FlowID: s.id,
			Type:   SignalTypeError,
			Error:  errPp,
		}
		return
	}

	if errPp == nil {
		ppVer := proxyProtocolVersions[ppHeader.Version]
		log.Info("Encountered PROXY protocol", zap.Any("header", ppHeader), zap.String("pp-version", ppVer))
		signals <- Signal{
			FlowID:            s.id,
			Type:              SignalTypeProxyProtocolHeader,
			PPSourceAddr:      ppHeader.SourceAddr,
			PPDestinationAddr: ppHeader.DestinationAddr,
			PPVersion:         ppVer,
		}
	}

	// peek into the tls handshake
	helloServerName, clientHelloEncountered := "", false
	_ = tls.Server(readOnlyConn{reader: buf}, &tls.Config{ //nolint:gosec
		GetConfigForClient: func(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
			if helloInfo != nil {
				helloServerName = helloInfo.ServerName
				clientHelloEncountered = true
			}
			return nil, nil
		},
	}).HandshakeContext(ctx)

	if clientHelloEncountered {
		log.Info("Encountered TLS handshake", zap.String("SNI", helloServerName))
		signals <- Signal{
			FlowID:        s.id,
			Type:          SignalTypeTLSClientHello,
			TLSServerName: helloServerName,
		}
	}
}

func drainReader(r io.Reader) {
	for {
		_, err := tcpreader.DiscardBytesToFirstError(r)
		if errors.Is(err, io.EOF) {
			return
		}
		if err == nil {
			continue
		}
		// to prevent costly infinite loop on non-EOF errors
		time.Sleep(1 * time.Millisecond)
	}
}

func NewSNICapturer(captureType CaptureType, ifaceName, bpf string) *SNICapturer {
	return &SNICapturer{
		ifaceName:   ifaceName,
		bpfFilter:   bpf,
		output:      make(chan Signal, 1024),
		captureType: captureType,
	}
}

func (s *SNICapturer) Output() <-chan Signal {
	return s.output
}

func (s *SNICapturer) Start(ctx context.Context, log *zap.Logger) error {
	var err error

	s.packetSource, err = s.acquireCaptureHandle()
	if err != nil {
		return fmt.Errorf("failed to acquire capture handle: %w", err)
	}

	streamFactory := newStreamFactory(ctx, log, s.output)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packets := s.packetSource.Packets()

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		defer close(s.output)
		for {
			select {
			case packet := <-packets:
				// A nil packet indicates the end of a pcap file.
				if packet == nil {
					return
				}
				if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
					continue
				}
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			case <-ctx.Done():
				log.Info("context expired")
				return
			case <-ticker.C:
				assembler.FlushOlderThan(time.Now().Add(-30 * time.Second))
			}
		}
	}()
	log.Info("capturer started")
	return nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) } //nolint:wrapcheck
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

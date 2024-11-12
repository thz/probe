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

//go:build linux
// +build linux

package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

func (s *SNICapturer) acquireCaptureHandle() (*gopacket.PacketSource, error) {
	switch s.captureType {
	case "pcap":
		pcapHandle, err := pcap.OpenLive(s.ifaceName, 2000, false, pcap.BlockForever)
		if err != nil {
			return nil, fmt.Errorf("failed to open interface %s: %w", s.ifaceName, err)
		}
		if s.bpfFilter != "" {
			pcapHandle.SetBPFFilter(s.bpfFilter)
		}
		s.packetSource = gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	case "afpacket":
		afpHandle, err := afpacket.NewTPacket(
			afpacket.OptInterface(s.ifaceName),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to open interface %s: %w", s.ifaceName, err)
		}
		if s.bpfFilter != "" {
			bpfInstr, err := compilePfg(s.bpfFilter, 2000)
			if err != nil {
				return nil, fmt.Errorf("failed to compile bpf filter %s: %w", s.bpfFilter, err)
			}
			afpHandle.SetBPF(bpfInstr)
		}
		return gopacket.NewPacketSource(afpHandle, layers.LinkTypeEthernet), nil
	}

	return nil, fmt.Errorf("unsupported type %s", s.captureType)
}

func compilePfg(filter string, snaplen int) ([]bpf.RawInstruction, error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return nil, err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	return bpfIns, nil
}

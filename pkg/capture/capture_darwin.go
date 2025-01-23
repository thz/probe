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

//go:build darwin
// +build darwin

package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var errInvalidConfig = fmt.Errorf("invalid config")

func (s *SNICapturer) acquireCaptureHandle() (*gopacket.PacketSource, error) {
	if s.captureType == CaptureTypePcapFile {

		handle, err := pcap.OpenOffline(s.ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to open pcap file %s: %w", s.ifaceName, err)
		}
		return gopacket.NewPacketSource(handle, handle.LinkType()), nil

	}

	return nil, fmt.Errorf("%w: unsupported type %s", errInvalidConfig, s.captureType)
}

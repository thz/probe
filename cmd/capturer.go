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

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/paraopsde/go-x/pkg/util"
	"github.com/spf13/cobra"
	"github.com/thz/probe/pkg/capture"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type captureOptions struct {
	verbose     bool
	captureType string
	iface       string
	bpfFilter   string
}

var captureOpts captureOptions

func captureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture [--verbose] --iface interface --bpf filter",
		Short: "Capture packets, report proxy protocol and SNI",
		Long: `The capture command will capture packets on the given interface and
report observed proxy protocol headers (v1/v2) and the SNI (Server Name Indication)
observed in a client-hello of TLS handshakes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 86400*time.Second)
			defer cancel()

			logLevel := zapcore.InfoLevel
			if captureOpts.verbose {
				logLevel = zapcore.DebugLevel
			}
			var logger *zap.Logger
			if captureOpts.verbose {
				logger = util.NewLoggerWithLevel(logLevel).WithOptions(zap.WithCaller(false))
			} else {
				logger = zap.NewNop()
			}

			capturer := capture.NewSNICapturer(capture.CaptureType(captureOpts.captureType), captureOpts.iface, captureOpts.bpfFilter)

			if err := capturer.Start(ctx, logger); err != nil {
				return fmt.Errorf("failed to start capturer: %w", err)
			}
			for x := range capturer.Output() {
				fmt.Println(x)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&captureOpts.verbose, "verbose", false, "be verbose")
	cmd.Flags().StringVar(&captureOpts.captureType, "capture", "afpacket", "system interface to use for packet capture (pcap/afpacket)")
	cmd.Flags().StringVar(&captureOpts.iface, "iface", "eth0", "interface to capture from")
	cmd.Flags().StringVar(&captureOpts.bpfFilter, "bpf", "", "set BPF filter for packet capture")

	return cmd
}

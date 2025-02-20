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

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/paraopsde/go-x/pkg/util"
	"github.com/spf13/cobra"
	"github.com/thz/probe/pkg/probe"
	"go.uber.org/zap/zapcore"
)

type probeOptions struct {
	verbose         bool
	showCertDetails bool
	ppv1, ppv2      bool
	sni             string
}

var probeOpts probeOptions

var (
	errInvalidArgument = fmt.Errorf("invalid argument")
)

func probeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe endpoint:port",
		Args:  cobra.ExactArgs(1),
		Short: "Probe a given endpoint (host:port)",
		Long: `Probe takes an endpoint in the form host:port as argument.

It will resolve the specified host, open a TCP connection,
and upgrade the connection TLS by performing a TLS handshake.
It will report details on DNS resolving (chain of CNAMEs / A records) and
about the observed server's certificate.
Optionally proxy protocol headers (v1/v2) are sent before the TLS handshake.
An explicit SNI (Server Name Indication) can be provided, which is then
used instead of the literal endpoint host name.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("%w: no endpoint provided", errInvalidArgument)
			}
			endpoint := args[0]

			var ppMode probe.ProxyProtocolMode
			if probeOpts.ppv1 {
				ppMode = probe.ProxyProtocolV1
			}
			if probeOpts.ppv2 {
				ppMode = probe.ProxyProtocolV2
			}
			proberOptions := probe.ProbeOptions{
				Endpoint:          endpoint,
				ProxyProtocolMode: probe.ProxyProtocolMode(ppMode),
			}

			if probeOpts.sni != "" {
				proberOptions.ServerNameIndication = probeOpts.sni
			}
			if probeOpts.showCertDetails {
				proberOptions.PrintCertDetails = true
			}
			prober, err := probe.NewProber(proberOptions)

			if err != nil {
				return fmt.Errorf("failed to create prober: %w", err)
			}

			// create context with 15 seconds timeout
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			logLevel := zapcore.WarnLevel
			if probeOpts.verbose {
				logLevel = zapcore.DebugLevel
			}
			ctx = util.CtxWithLog(ctx, util.NewLoggerWithLevel(logLevel))

			err = prober.Probe(ctx)
			if err != nil {
				return fmt.Errorf("failed to probe: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&probeOpts.verbose, "verbose", false, "be verbose, output logs")
	cmd.Flags().BoolVar(&probeOpts.showCertDetails, "cert-details", false, "show certificate details (SANs, validity)")
	cmd.Flags().BoolVar(&probeOpts.ppv1, "proxy-protocol-v1", false, "send proxy protocol v1 headers")
	cmd.Flags().BoolVar(&probeOpts.ppv2, "proxy-protocol-v2", false, "send proxy protocol v2 headers")
	cmd.Flags().StringVar(&probeOpts.sni, "sni", "", "set SNI for TLS handshake (defaults to endpoint host)")

	return cmd
}

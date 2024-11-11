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
	verbose    bool
	ppv1, ppv2 bool
	sni        string
}

var probeOpts probeOptions

func probeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe [--verbose] [--proxy-protocol-v1|--proxy-protocol-v2] [--sni server-name] endpoint",
		Short: "Probe a given endpoint",
		Long: `Probe will open a TLS connection to an endpoint.
It will report details on DNS resolving (chain of CNAMEs / A records).
The command also supports sending proxy protocol headers (v1/v2) and
setting the SNI (Server Name Indication) for the TLS handshake.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("endpoint expected as argument")
			}
			endpoint := args[0]

			pp := ""
			if probeOpts.ppv1 {
				pp = "v1"
			}
			if probeOpts.ppv2 {
				pp = "v2"
			}
			proberOptions := probe.ProbeOptions{
				Endpoint:      endpoint,
				ProxyProtocol: pp,
			}

			if probeOpts.sni != "" {
				proberOptions.ServerNameIndication = probeOpts.sni
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
	cmd.Flags().BoolVar(&probeOpts.ppv1, "proxy-protocol-v1", false, "send proxy protocol v1 headers")
	cmd.Flags().BoolVar(&probeOpts.ppv2, "proxy-protocol-v2", false, "send proxy protocol v2 headers")
	cmd.Flags().StringVar(&probeOpts.sni, "sni", "", "set SNI for TLS handshake (defaults to endpoint host)")

	return cmd
}

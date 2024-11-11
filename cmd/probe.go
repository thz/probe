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
	verbose bool
	sni     string
}

var probeOpts probeOptions

func probeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe [--verbose] [--sni server-name] endpoint",
		Short: "Probe a given endpoint",
		Long: `Probe will open a TLS connection to an endpoint.
It will report details on DNS resolving (chain of CNAMEs / A records).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("endpoint expected as argument")
			}
			endpoint := args[0]

			proberOptions := probe.ProbeOptions{
				Endpoint: endpoint,
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
	cmd.Flags().StringVar(&probeOpts.sni, "sni", "", "set SNI for TLS handshake (defaults to endpoint host)")

	return cmd
}

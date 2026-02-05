//
// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
)

// Initialize adds flags that are shared between all Rekor binaries
func Initialize(serveCmd *cobra.Command) error {
	// server configs
	serveCmd.Flags().Bool("read-only", false, "whether the log should accept new entries")
	serveCmd.Flags().Int("http-port", 3000, "HTTP port to bind to")
	serveCmd.Flags().String("http-address", "127.0.0.1", "HTTP address to bind to")
	serveCmd.Flags().Int("http-metrics-port", 2112, "HTTP port to bind metrics to")
	serveCmd.Flags().Int("grpc-port", 3001, "GRPC port to bind to")
	serveCmd.Flags().String("grpc-address", "127.0.0.1", "GRPC address to bind to")
	serveCmd.Flags().Duration("server-timeout", 20*time.Second, "timeout settings for gRPC and HTTP connections")
	serveCmd.Flags().Int("max-request-body-size", 4*1024*1024, "maximum request body size in bytes")
	serveCmd.Flags().String("log-level", "info", "log level for the process. options are [debug, info, warn, error]")
	serveCmd.Flags().Bool("request-response-logging", false, "enables logging of request and response content; log-level must be 'debug' for this to take effect")
	serveCmd.Flags().String("grpc-tls-cert-file", "", "optional TLS certificate for serving gRPC over TLS")
	serveCmd.Flags().String("grpc-tls-key-file", "", "optional TLS private key for serving gRPC over TLS")
	serveCmd.Flags().String("http-tls-cert-file", "", "optional TLS certificate for serving HTTP over TLS")
	serveCmd.Flags().String("http-tls-key-file", "", "optional TLS private key for serving HTTP over TLS")

	// hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	serveCmd.Flags().String("hostname", hostname, "public hostname, used as the checkpoint origin")

	// tessera lifecycle configs
	serveCmd.Flags().Uint("batch-max-size", tessera.DefaultBatchMaxSize, "the maximum number of entries that will accumulated before being sent to the sequencer")
	serveCmd.Flags().Duration("batch-max-age", tessera.DefaultBatchMaxAge, "the maximum amount of time a batch of entries will wait before being sent to the sequencer")
	serveCmd.Flags().Duration("checkpoint-interval", tessera.DefaultCheckpointInterval, "the frequency at which a checkpoint will be published")
	serveCmd.Flags().Uint("pushback-max-outstanding", tessera.DefaultPushbackMaxOutstanding, "the maximum number of 'in-flight' add requests")
	serveCmd.Flags().Duration("tlog-timeout", 30*time.Second, "timeout for terminating the tiles log queue")

	// antispam configs
	serveCmd.Flags().Bool("persistent-antispam", false, "whether to enable persistent antispam measures")
	serveCmd.Flags().Uint("antispam-max-batch-size", 0, "maximum batch size for deduplication operations; will default to Tessera recommendation if unset; for Spanner, recommend around 1500 with 300 or more PU, or around 64 for smaller (e.g. 100 PU) instances")
	serveCmd.Flags().Uint("antispam-pushback-threshold", 0, "maximum number of 'in-flight' add requests the antispam operator will allow before pushing back; will default to Tessera recommendation if unset")

	// witness configs
	serveCmd.Flags().String("witness-policy-path", "", "optional path to witness policy file")

	// allowed entry signing algorithms
	keyAlgorithmTypes, err := defaultKeyAlgorithms()
	if err != nil {
		return err
	}
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	serveCmd.Flags().StringSlice("client-signing-algorithms", keyAlgorithmTypes, keyAlgorithmHelp)

	return nil
}

func defaultKeyAlgorithms() ([]string, error) {
	allowedClientSigningAlgorithms := algorithmregistry.AllowedClientSigningAlgorithms
	keyAlgorithmTypes := []string{}
	for _, keyAlgorithm := range allowedClientSigningAlgorithms {
		keyFlag, err := signature.FormatSignatureAlgorithmFlag(keyAlgorithm)
		if err != nil {
			return nil, err
		}
		keyAlgorithmTypes = append(keyAlgorithmTypes, keyFlag)
	}
	sort.Strings(keyAlgorithmTypes)
	return keyAlgorithmTypes, nil
}

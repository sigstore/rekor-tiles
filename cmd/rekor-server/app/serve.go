//go:build aws || gcp

//
// Copyright 2025 The Sigstore Authors.
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

package app

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"
	"sigs.k8s.io/release-utils/version"

	rekorapp "github.com/sigstore/rekor-tiles/v2/internal/rekor/app"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
)

// initServeCmd initializes the serve command with backend-specific configuration
func initServeCmd(backend BackendConfig) {
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "start the Rekor server (" + backend.Name() + ")",
		Long:  "start the Rekor server with " + backend.Name() + " storage backend",
		Run: func(cmd *cobra.Command, _ []string) {
			ctx := cmd.Context()

			logLevel := slog.LevelInfo
			if err := logLevel.UnmarshalText([]byte(viper.GetString("log-level"))); err != nil {
				slog.Error("invalid log-level specified; must be one of 'debug', 'info', 'error', or 'warn'")
				os.Exit(1)
			}

			// Setup backend-specific logger
			logger := backend.SetupLogger(logLevel)
			slog.SetDefault(logger)

			// tessera uses klog so pipe all klog messages to be written through slog
			klog.SetSlogLogger(slog.Default())

			slog.Info("starting rekor-server-"+backend.Name(), "version", version.GetVersionInfo())

			// Set up backend-specific KMS signer options
			SetBackendKMSSignerOptions(backend)

			// Get backend-specific driver configuration
			driverConfig, err := backend.GetDriverConfig()
			if err != nil {
				slog.Error("failed to get driver config", "error", err)
				os.Exit(1)
			}

			if err := rekorapp.RunServer(ctx, driverConfig); err != nil {
				slog.Error("failed to run server", "error", err)
				os.Exit(1)
			}
		},
	}

	// Register common flags
	registerCommonFlags(serveCmd)

	// Register backend-specific flags
	backend.RegisterFlags(serveCmd)

	if err := viper.BindPFlags(serveCmd.Flags()); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	rootCmd.AddCommand(serveCmd)
}

// registerCommonFlags registers flags common to all backends
func registerCommonFlags(cmd *cobra.Command) {
	// server configs
	cmd.Flags().Bool("read-only", false, "whether the log should accept new entries")
	cmd.Flags().Int("http-port", 3000, "HTTP port to bind to")
	cmd.Flags().String("http-address", "127.0.0.1", "HTTP address to bind to")
	cmd.Flags().Int("http-metrics-port", 2112, "HTTP port to bind metrics to")
	cmd.Flags().Int("grpc-port", 3001, "GRPC port to bind to")
	cmd.Flags().String("grpc-address", "127.0.0.1", "GRPC address to bind to")
	cmd.Flags().Duration("server-timeout", 20*time.Second, "timeout settings for gRPC and HTTP connections")
	cmd.Flags().Int("max-request-body-size", 4*1024*1024, "maximum request body size in bytes")
	cmd.Flags().String("log-level", "info", "log level for the process. options are [debug, info, warn, error]")
	cmd.Flags().Bool("request-response-logging", false, "enables logging of request and response content; log-level must be 'debug' for this to take effect")
	cmd.Flags().String("grpc-tls-cert-file", "", "optional TLS certificate for serving gRPC over TLS")
	cmd.Flags().String("grpc-tls-key-file", "", "optional TLS private key for serving gRPC over TLS")
	cmd.Flags().String("http-tls-cert-file", "", "optional TLS certificate for serving HTTP over TLS")
	cmd.Flags().String("http-tls-key-file", "", "optional TLS private key for serving HTTP over TLS")

	// hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	cmd.Flags().String("hostname", hostname, "public hostname, used as the checkpoint origin")

	// checkpoint signing configs (common to all backends)
	cmd.Flags().String("signer-filepath", "", "path to the signing key")
	cmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	cmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	cmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")

	// tessera lifecycle configs
	cmd.Flags().Uint("batch-max-size", tessera.DefaultBatchMaxSize, "the maximum number of entries that will accumulated before being sent to the sequencer")
	cmd.Flags().Duration("batch-max-age", tessera.DefaultBatchMaxAge, "the maximum amount of time a batch of entries will wait before being sent to the sequencer")
	cmd.Flags().Duration("checkpoint-interval", tessera.DefaultCheckpointInterval, "the frequency at which a checkpoint will be published")
	cmd.Flags().Uint("pushback-max-outstanding", tessera.DefaultPushbackMaxOutstanding, "the maximum number of 'in-flight' add requests")
	cmd.Flags().Duration("tlog-timeout", 30*time.Second, "timeout for terminating the tiles log queue")

	// antispam configs
	cmd.Flags().Bool("persistent-antispam", false, "whether to enable persistent antispam measures")
	cmd.Flags().Uint("antispam-max-batch-size", 0, "maximum batch size for deduplication operations; will default to Tessera recommendation if unset")
	cmd.Flags().Uint("antispam-pushback-threshold", 0, "maximum number of 'in-flight' add requests the antispam operator will allow before pushing back; will default to Tessera recommendation if unset")

	// allowed entry signing algorithms
	keyAlgorithmTypes, err := rekorapp.DefaultKeyAlgorithms()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	cmd.Flags().StringSlice("client-signing-algorithms", keyAlgorithmTypes, keyAlgorithmHelp)
}

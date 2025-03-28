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
	"crypto"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor-tiles/pkg/server"
	"github.com/sigstore/rekor-tiles/pkg/signer"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the Rekor server",
	Long:  "start the Rekor server",
	Run: func(cmd *cobra.Command, _ []string) {
		ctx := cmd.Context()
		versionInfo := version.GetVersionInfo()
		versionInfoStr, err := versionInfo.JSONString()
		if err != nil {
			versionInfoStr = versionInfo.String()
		}
		slog.Info("starting rekor-server", "version", versionInfoStr)

		// currently only the GCP driver is supported for rekor-tiles.
		tesseraDriver, err := tessera.NewGCPDriver(ctx, viper.GetString("gcp-bucket"), viper.GetString("gcp-spanner"))
		if err != nil {
			slog.Error(fmt.Sprintf("failed to initialize GCP driver: %v", err.Error()))
			os.Exit(1)
		}
		var signerOpts []signer.Option
		switch {
		case viper.GetString("signer-filepath") != "":
			signerOpts = []signer.Option{signer.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}
		case viper.GetString("signer-kmskey") != "":
			kmshash := viper.GetString("signer-kmshash")
			hashAlg, ok := hashAlgMap[kmshash]
			if !ok {
				slog.Error(fmt.Sprintf("invalid hash algorithm for --signer-kmshash: %s", kmshash))
				os.Exit(1)
			}
			signerOpts = []signer.Option{signer.WithKMS(viper.GetString("signer-kmskey"), hashAlg)}
		case viper.GetString("signer-tink-kek-uri") != "":
			signerOpts = []signer.Option{signer.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}
		default:
			slog.Error("must provide a signer using a file, KMS, or Tink")
			os.Exit(1)
		}
		signer, err := signer.New(ctx, signerOpts...)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to initialize signer: %v", err.Error()))
			os.Exit(1)
		}
		appendOptions, err := tessera.NewAppendOptions(ctx, viper.GetString("hostname"), signer)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to initialize append options: %v", err))
			os.Exit(1)
		}
		appendOptions = tessera.WithLifecycleOptions(appendOptions, viper.GetUint("batch-max-size"), viper.GetDuration("batch-max-age"), viper.GetDuration("checkpoint-interval"), viper.GetUint("pushback-max-outstanding"))
		appendOptions, err = tessera.WithAntispamOptions(ctx, appendOptions, viper.GetBool("persistent-antispam"), viper.GetUint("antispam-max-batch-size"), viper.GetUint("antispam-pushback-threshold"), viper.GetString("gcp-spanner"))
		if err != nil {
			slog.Error(fmt.Sprintf("failed to configure antispam append options: %v", err))
			os.Exit(1)
		}
		tesseraStorage, err := tessera.NewStorage(ctx, viper.GetString("hostname"), tesseraDriver, appendOptions)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to initialize tessera storage: %v", err.Error()))
			os.Exit(1)
		}

		server.Serve(
			ctx,
			server.NewHTTPConfig(
				server.WithHTTPPort(viper.GetInt("http-port")),
				server.WithHTTPHost(viper.GetString("http-address")),
				server.WithHTTPMetricsPort(viper.GetInt("http-metrics-port"))),
			server.NewGRPCConfig(
				server.WithGRPCPort(viper.GetInt("grpc-port")),
				server.WithGRPCHost(viper.GetString("grpc-address"))),
			server.NewServer(tesseraStorage),
		)
	},
}

func init() {
	// server configs
	serveCmd.Flags().Int("http-port", 3000, "HTTP port to bind to")
	serveCmd.Flags().String("http-address", "127.0.0.1", "HTTP address to bind to")
	serveCmd.Flags().Int("http-metrics-port", 2112, "HTTP port to bind metrics to")
	serveCmd.Flags().Int("grpc-port", 3001, "GRPC port to bind to")
	serveCmd.Flags().String("grpc-address", "127.0.0.1", "GRPC address to bind to")
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	serveCmd.Flags().String("hostname", hostname, "public hostname, used as the checkpoint origin")

	// gcp configs
	serveCmd.Flags().String("gcp-bucket", "", "GCS bucket for tile and checkpoint storage")
	serveCmd.Flags().String("gcp-spanner", "", "Spanner database URI")

	// checkpoint signing configs
	serveCmd.Flags().String("signer-filepath", "", "path to the signing key")
	serveCmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	serveCmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of awskms://keyname, azurekms://keyname, gcpkms://keyname, or hashivault://keyname")
	serveCmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	serveCmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset. Valid options are [aws-kms://keyname, gcp-kms://keyname]")
	serveCmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")

	// tessera lifecycle configs
	serveCmd.Flags().Uint("batch-max-size", tessera.DefaultBatchMaxSize, "the maximum number of entries that will accumulated before being sent to the sequencer")
	serveCmd.Flags().Duration("batch-max-age", tessera.DefaultBatchMaxAge, "the maximum amount of time a batch of entries will wait before being sent to the sequencer")
	serveCmd.Flags().Duration("checkpoint-interval", tessera.DefaultCheckpointInterval, "the frequency at which a checkpoint will be published")
	serveCmd.Flags().Uint("pushback-max-outstanding", tessera.DefaultPushbackMaxOutstanding, "the maximum number of 'in-flight' add requests")

	// antispam configs
	serveCmd.Flags().Bool("persistent-antispam", false, "whether to enable persistent antispam measures; only available for GCP storage backend and not supported by the Spanner storage emulator")
	serveCmd.Flags().Uint("antispam-max-batch-size", tessera.DefaultAntispamMaxBatchSize, "maximum batch size for deduplication operations; recommend around 1500 for Spanner instances with 300 or more PU, or around 64 for smaller (e.g. 100 PU) instances")
	serveCmd.Flags().Uint("antispam-pushback-threshold", tessera.DefaultAntispamPushbackThreshold, "maximum number of 'in-flight' add requests the antispam operator will allow before pushing back")

	if err := viper.BindPFlags(serveCmd.Flags()); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(serveCmd)
}

var hashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

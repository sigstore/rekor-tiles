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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	clog "github.com/chainguard-dev/clog/gcp"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/server"
	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the Rekor server",
	Long:  "start the Rekor server",
	Run: func(cmd *cobra.Command, _ []string) {
		ctx := cmd.Context()

		logLevel := slog.LevelInfo
		if err := logLevel.UnmarshalText([]byte(viper.GetString("log-level"))); err != nil {
			slog.Error("invalid log-level specified; must be one of 'debug', 'info', 'error', or 'warn'")
			os.Exit(1)
		}
		slog.SetDefault(slog.New(clog.NewHandler(logLevel)))

		// tessera uses klog so pipe all klog messages to be written through slog
		klog.SetSlogLogger(slog.Default())

		slog.Info("starting rekor-server", "version", version.GetVersionInfo())

		shutdownOtel := initOTel(ctx)
		defer shutdownOtel(ctx)

		var signerOpts []signerverifier.Option
		switch {
		case viper.GetString("signer-filepath") != "":
			signerOpts = []signerverifier.Option{signerverifier.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}
		case viper.GetString("signer-kmskey") != "":
			kmshash := viper.GetString("signer-kmshash")
			hashAlg, ok := hashAlgMap[kmshash]
			if !ok {
				slog.Error("invalid hash algorithm for --signer-kmshash", "algorithm", kmshash)
				os.Exit(1)
			}
			// initialize optional RPC options for GCP KMS
			rpcOpts := make([]signature.RPCOption, 0)
			callOpts := []grpc_retry.CallOption{grpc_retry.WithMax(viper.GetUint("gcp-kms-retries")), grpc_retry.WithPerRetryTimeout(time.Duration(viper.GetUint32("gcp-kms-timeout")) * time.Second)}
			rpcOpts = append(rpcOpts, gcp.WithGoogleAPIClientOption(option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))))

			signerOpts = []signerverifier.Option{signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg, rpcOpts)}
		case viper.GetString("signer-tink-kek-uri") != "":
			signerOpts = []signerverifier.Option{signerverifier.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}
		default:
			slog.Error("no signer configured; must provide a signer using a file, KMS, or Tink")
			os.Exit(1)
		}
		signer, err := signerverifier.New(ctx, signerOpts...)
		if err != nil {
			slog.Error("failed to initialize signer", "error", err)
			os.Exit(1)
		}
		pubkey, err := signer.PublicKey()
		if err != nil {
			slog.Error("failed to get public key from signing key", "error", err)
			os.Exit(1)
		}
		der, err := x509.MarshalPKIXPublicKey(pubkey)
		if err != nil {
			slog.Error("failed to marshal public key to DER", "error", err)
			os.Exit(1)
		}
		slog.Info("Loaded signing key", "pubkey in base64 DER", base64.StdEncoding.EncodeToString(der))

		appendOptions, err := tessera.NewAppendOptions(ctx, viper.GetString("hostname"), signer)
		if err != nil {
			slog.Error("failed to initialize append options", "error", err)
			os.Exit(1)
		}
		// Compute log ID for TransparencyLogEntry, to be used by clients to look up
		// the correct instance in a trust root. Log ID is equivalent to the non-truncated
		// hash of the public key and origin per the signed-note C2SP spec.
		pubKey, err := signer.PublicKey(options.WithContext(ctx))
		if err != nil {
			slog.Error("failed to get public key", "error", err)
			os.Exit(1)
		}
		_, logID, err := note.KeyHash(viper.GetString("hostname"), pubKey)
		if err != nil {
			slog.Error("failed to get log ID", "error", err)
			os.Exit(1)
		}

		readOnly := viper.GetBool("read-only")
		var tesseraStorage tessera.Storage
		shutdownFn := func(_ context.Context) error { return nil }
		// if in read-only mode, don't start the appender, because we don't want new checkpoints being published.
		if !readOnly {
			driverConfig := tessera.DriverConfiguration{
				Hostname:            viper.GetString("hostname"),
				GCPBucket:           viper.GetString("gcp-bucket"),
				GCPSpannerDB:        viper.GetString("gcp-spanner"),
				AWSBucket:           viper.GetString("aws-bucket"),
				AWSMySQLDSN:         viper.GetString("aws-mysql-dsn"),
				PersistentAntispam:  viper.GetBool("persistent-antispam"),
				ASMaxBatchSize:      viper.GetUint("antispam-max-batch-size"),
				ASPushbackThreshold: viper.GetUint("antispam-pushback-threshold"),
			}
			tesseraDriver, persistentAntispam, err := tessera.NewDriver(ctx, driverConfig)
			if err != nil {
				slog.Error("failed to initialize driver", "error", err)
				os.Exit(1)
			}
			appendOptions = tessera.WithLifecycleOptions(appendOptions, viper.GetUint("batch-max-size"), viper.GetDuration("batch-max-age"), viper.GetDuration("checkpoint-interval"), viper.GetUint("pushback-max-outstanding"))
			appendOptions = tessera.WithAntispamOptions(appendOptions, persistentAntispam)
			tesseraStorage, shutdownFn, err = tessera.NewStorage(ctx, viper.GetString("hostname"), tesseraDriver, appendOptions)
			if err != nil {
				slog.Error("failed to initialize tessera storage", "error", err)
				os.Exit(1)
			}
		}
		algorithmRegistry, err := algorithmregistry.AlgorithmRegistry(viper.GetStringSlice("client-signing-algorithms"))
		if err != nil {
			slog.Error("failed to get algorithm registry", "error", err)
			os.Exit(1)
		}

		rekorServer := server.NewServer(tesseraStorage, readOnly, algorithmRegistry, logID)

		server.Serve(
			ctx,
			server.NewHTTPConfig(
				server.WithHTTPPort(viper.GetInt("http-port")),
				server.WithHTTPHost(viper.GetString("http-address")),
				server.WithHTTPTimeout(viper.GetDuration("server-timeout")),
				server.WithHTTPMaxRequestBodySize(viper.GetInt("max-request-body-size")),
				server.WithHTTPMetricsPort(viper.GetInt("http-metrics-port")),
				server.WithHTTPTLSCredentials(viper.GetString("http-tls-cert-file"), viper.GetString("http-tls-key-file")),
				server.WithGRPCTLSCredentials(viper.GetString("grpc-tls-cert-file")),
			),
			server.NewGRPCConfig(
				server.WithGRPCPort(viper.GetInt("grpc-port")),
				server.WithGRPCHost(viper.GetString("grpc-address")),
				server.WithGRPCTimeout(viper.GetDuration("server-timeout")),
				server.WithGRPCMaxMessageSize(viper.GetInt("max-request-body-size")),
				server.WithGRPCLogLevel(logLevel, viper.GetBool("request-response-logging")),
				server.WithTLSCredentials(viper.GetString("grpc-tls-cert-file"), viper.GetString("grpc-tls-key-file")),
			),
			viper.GetDuration("tlog-timeout"),
			rekorServer,
			shutdownFn,
		)
	},
}

func init() {
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

	// gcp configs
	serveCmd.Flags().String("gcp-bucket", "", "GCS bucket for tile and checkpoint storage")
	serveCmd.Flags().String("gcp-spanner", "", "Spanner database URI")

	// aws configs
	serveCmd.Flags().String("aws-bucket", "", "S3 bucket for tile and checkpoint storage")
	serveCmd.Flags().String("aws-mysql-dsn", "", "MySQL DSN for Aurora/RDS (e.g., user:pass@tcp(host:3306)/dbname)")

	// checkpoint signing configs
	serveCmd.Flags().String("signer-filepath", "", "path to the signing key")
	serveCmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	serveCmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of awskms://keyname, azurekms://keyname, gcpkms://keyname, or hashivault://keyname")
	serveCmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	serveCmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset. Valid options are [aws-kms://keyname, gcp-kms://keyname]")
	serveCmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")
	serveCmd.Flags().Uint("gcp-kms-retries", 0, "number of retries for GCP KMS requests")
	serveCmd.Flags().Uint32("gcp-kms-timeout", 0, "sets the RPC timeout per call for GCP KMS requests in seconds, defaults to 0 (no timeout)")

	// tessera lifecycle configs
	serveCmd.Flags().Uint("batch-max-size", tessera.DefaultBatchMaxSize, "the maximum number of entries that will accumulated before being sent to the sequencer")
	serveCmd.Flags().Duration("batch-max-age", tessera.DefaultBatchMaxAge, "the maximum amount of time a batch of entries will wait before being sent to the sequencer")
	serveCmd.Flags().Duration("checkpoint-interval", tessera.DefaultCheckpointInterval, "the frequency at which a checkpoint will be published")
	serveCmd.Flags().Uint("pushback-max-outstanding", tessera.DefaultPushbackMaxOutstanding, "the maximum number of 'in-flight' add requests")
	serveCmd.Flags().Duration("tlog-timeout", 30*time.Second, "timeout for terminating the tiles log queue")

	// antispam configs
	serveCmd.Flags().Bool("persistent-antispam", false, "whether to enable persistent antispam measures; available for GCP (Spanner) and AWS (MySQL) storage backends; not supported by the Spanner storage emulator")
	serveCmd.Flags().Uint("antispam-max-batch-size", 0, "maximum batch size for deduplication operations; will default to Tessera recommendation if unset; for Spanner, recommend around 1500 with 300 or more PU, or around 64 for smaller (e.g. 100 PU) instances")
	serveCmd.Flags().Uint("antispam-pushback-threshold", 0, "maximum number of 'in-flight' add requests the antispam operator will allow before pushing back; will default to Tessera recommendation if unset")

	// allowed entry signing algorithms
	keyAlgorithmTypes, err := defaultKeyAlgorithms()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	serveCmd.Flags().StringSlice("client-signing-algorithms", keyAlgorithmTypes, keyAlgorithmHelp)

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

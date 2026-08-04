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

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/cli"
	"github.com/sigstore/rekor-tiles/v2/internal/server"
	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	posixDriver "github.com/sigstore/rekor-tiles/v2/internal/tessera/posix"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"
	"sigs.k8s.io/release-utils/version"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the Rekor server",
	Long:  "start the Rekor server",
	Run: func(cmd *cobra.Command, _ []string) {
		runServer(cmd, false)
	},
}

var serveIdentityCmd = &cobra.Command{
	Use:   "serve-identity",
	Short: "start the Rekor identity usage server",
	Long:  "start the Rekor identity usage server",
	Run: func(cmd *cobra.Command, _ []string) {
		runServer(cmd, true)
	},
}

func runServer(cmd *cobra.Command, isIdentity bool) {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	ctx := cmd.Context()

	logLevel := slog.LevelInfo
	if err := logLevel.UnmarshalText([]byte(viper.GetString("log-level"))); err != nil {
		slog.Error("invalid log-level specified; must be one of 'debug', 'info', 'error', or 'warn'")
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// tessera uses klog so pipe all klog messages to be written through slog
	klog.SetSlogLogger(slog.Default())

	slog.Info("starting rekor-server", "version", version.GetVersionInfo(), "identity_mode", isIdentity)

	if viper.GetString("signer-filepath") == "" {
		slog.Error("--signer-filepath must be set")
		os.Exit(1)
	}
	signer, err := signerverifier.NewFileSignerVerifier(viper.GetString("signer-filepath"), viper.GetString("signer-password"))
	if err != nil {
		slog.Error("failed to initialize signer", "error", err)
		os.Exit(1)
	}
	pubkey, err := signer.PublicKey()
	if err != nil {
		slog.Error("failed to get public key from signing key", "error", err)
		os.Exit(1)
	}
	var der []byte
	switch pk := pubkey.(type) {
	case *mldsa.PublicKey:
		der, err = mldsax509.MarshalPKIXPublicKey(pk)
	case ed25519.PublicKey:
		der, err = x509.MarshalPKIXPublicKey(pk)
	default:
		slog.Error("unsupported log signing key algorithm, must be Ed25519 or ML-DSA")
		os.Exit(1)
	}
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
		driverConfig := posixDriver.DriverConfiguration{
			StorageDir:          viper.GetString("storage-dir"),
			PersistentAntispam:  viper.GetBool("persistent-antispam"),
			ASMaxBatchSize:      viper.GetUint("antispam-max-batch-size"),
			ASPushbackThreshold: viper.GetUint("antispam-pushback-threshold"),
		}
		tesseraDriver, persistentAntispam, err := posixDriver.NewDriver(ctx, driverConfig)
		if err != nil {
			slog.Error("failed to initialize driver", "error", err)
			os.Exit(1)
		}
		appendOptions = tessera.WithLifecycleOptions(appendOptions, viper.GetUint("batch-max-size"), viper.GetDuration("batch-max-age"), viper.GetDuration("checkpoint-interval"), viper.GetUint("pushback-max-outstanding"))
		appendOptions = tessera.WithAntispamOptions(appendOptions, persistentAntispam)
		if wpf := viper.GetString("witness-policy-path"); wpf != "" {
			f, err := os.ReadFile(wpf)
			if err != nil {
				slog.Error("failed to read witness policy file", "file", wpf, "error", err)
				os.Exit(1)
			}
			appendOptions, err = tessera.WithWitnessing(appendOptions, f)
			if err != nil {
				slog.Error("failed to initialize witnessing", "error", err)
				os.Exit(1)
			}
		}
		tesseraStorage, shutdownFn, err = tessera.NewStorage(ctx, viper.GetString("hostname"), tesseraDriver, appendOptions)
		if err != nil {
			slog.Error("failed to initialize tessera storage", "error", err)
			os.Exit(1)
		}
	}
	algorithms := viper.GetStringSlice("client-signing-algorithms")
	if isIdentity {
		if !cmd.Flags().Changed("client-signing-algorithms") {
			algorithms = []string{"ed25519", "ml-dsa-44"}
		}
		for _, alg := range algorithms {
			if alg != "ed25519" && alg != "ml-dsa-44" {
				slog.Error(fmt.Sprintf("unsupported algorithm '%s' for identity log", alg))
				os.Exit(1)
			}
		}
	}

	algorithmRegistry, err := algorithmregistry.AlgorithmRegistry(algorithms)
	if err != nil {
		slog.Error("failed to get algorithm registry", "error", err)
		os.Exit(1)
	}

	var oidcConfig *config.FulcioConfig
	if oidcConfigPath := viper.GetString("oidc-config"); oidcConfigPath != "" {
		var err error
		oidcConfig, err = config.Load(oidcConfigPath)
		if err != nil {
			slog.Error("failed to load oidc config", "error", err)
			os.Exit(1)
		}
	}
	slog.Info("OIDC config loaded", "path", viper.GetString("oidc-config"), "isNil", oidcConfig == nil)

	var rekorServer server.Registrar
	if isIdentity {
		rekorServer = server.NewIdentityServer(tesseraStorage, readOnly, algorithmRegistry, oidcConfig)
	} else {
		rekorServer = server.NewServer(tesseraStorage, readOnly, algorithmRegistry, logID)
	}

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
}

func addFlags(cmd *cobra.Command) {
	if err := cli.Initialize(cmd); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// POSIX configs
	cmd.Flags().String("storage-dir", "", "directory for tile and checkpoint storage for a POSIX log")

	// checkpoint signing configs
	cmd.Flags().String("signer-filepath", "", "path to the signing key")
	cmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	cmd.Flags().String("oidc-config", "", "path to the OIDC configuration file")
}

func init() {
	addFlags(serveCmd)
	rootCmd.AddCommand(serveCmd)

	addFlags(serveIdentityCmd)
	rootCmd.AddCommand(serveIdentityCmd)
}

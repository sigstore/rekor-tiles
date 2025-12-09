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
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/server"
	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"
)

// RunServer starts the Rekor server with the provided tessera driver configuration
func RunServer(ctx context.Context, driverConfig tessera.DriverConfiguration) error {
	slog.Info("starting rekor-server", "version", version.GetVersionInfo())

	// Initialize signer
	signerOpts, err := getSignerOptions()
	if err != nil {
		return fmt.Errorf("getting signer options: %w", err)
	}
	signer, err := signerverifier.New(ctx, signerOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize signer: %w", err)
	}
	pubkey, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key from signing key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key to DER: %w", err)
	}
	slog.Info("Loaded signing key", "pubkey in base64 DER", base64.StdEncoding.EncodeToString(der))

	appendOptions, err := tessera.NewAppendOptions(ctx, viper.GetString("hostname"), signer)
	if err != nil {
		return fmt.Errorf("failed to initialize append options: %w", err)
	}
	// Compute log ID for TransparencyLogEntry, to be used by clients to look up
	// the correct instance in a trust root. Log ID is equivalent to the non-truncated
	// hash of the public key and origin per the signed-note C2SP spec.
	pubKey, err := signer.PublicKey(options.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	_, logID, err := note.KeyHash(viper.GetString("hostname"), pubKey)
	if err != nil {
		return fmt.Errorf("failed to get log ID: %w", err)
	}

	readOnly := viper.GetBool("read-only")
	var tesseraStorage tessera.Storage
	shutdownFn := func(_ context.Context) error { return nil }
	// if in read-only mode, don't start the appender, because we don't want new checkpoints being published.
	if !readOnly {
		tesseraDriver, persistentAntispam, err := tessera.NewDriver(ctx, driverConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize driver: %w", err)
		}
		appendOptions = tessera.WithLifecycleOptions(appendOptions, viper.GetUint("batch-max-size"), viper.GetDuration("batch-max-age"), viper.GetDuration("checkpoint-interval"), viper.GetUint("pushback-max-outstanding"))
		appendOptions = tessera.WithAntispamOptions(appendOptions, persistentAntispam)
		tesseraStorage, shutdownFn, err = tessera.NewStorage(ctx, viper.GetString("hostname"), tesseraDriver, appendOptions)
		if err != nil {
			return fmt.Errorf("failed to initialize tessera storage: %w", err)
		}
	}
	algorithmRegistry, err := algorithmregistry.AlgorithmRegistry(viper.GetStringSlice("client-signing-algorithms"))
	if err != nil {
		return fmt.Errorf("failed to get algorithm registry: %w", err)
	}

	rekorServer := server.NewServer(tesseraStorage, readOnly, algorithmRegistry, logID)

	logLevel := slog.LevelInfo
	if err := logLevel.UnmarshalText([]byte(viper.GetString("log-level"))); err != nil {
		return fmt.Errorf("invalid log-level specified: %w", err)
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
	return nil
}

func getSignerOptions() ([]signerverifier.Option, error) {
	switch {
	case viper.GetString("signer-filepath") != "":
		return []signerverifier.Option{signerverifier.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}, nil
	case viper.GetString("signer-kmskey") != "":
		return GetKMSSignerOptions()
	case viper.GetString("signer-tink-kek-uri") != "":
		return []signerverifier.Option{signerverifier.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}, nil
	default:
		return nil, fmt.Errorf("no signer configured; must provide a signer using a file, KMS, or Tink")
	}
}

// GetKMSSignerOptions returns the KMS signer options. This is implemented by each cloud-specific binary.
var GetKMSSignerOptions func() ([]signerverifier.Option, error)

func DefaultKeyAlgorithms() ([]string, error) {
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

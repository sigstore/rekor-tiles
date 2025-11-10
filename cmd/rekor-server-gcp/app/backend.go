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
	"time"

	clog "github.com/chainguard-dev/clog/gcp"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
)

// GCPBackend implements the BackendConfig interface for GCP
type GCPBackend struct{}

func (g *GCPBackend) Name() string {
	return "gcp"
}

func (g *GCPBackend) Description() string {
	return "Google Cloud Platform"
}

func (g *GCPBackend) SetupLogger(logLevel slog.Level) *slog.Logger {
	return slog.New(clog.NewHandler(logLevel))
}

func (g *GCPBackend) RegisterFlags(cmd *cobra.Command) {
	// GCP-specific storage configs
	cmd.Flags().String("gcp-bucket", "", "GCS bucket for tile and checkpoint storage")
	cmd.Flags().String("gcp-spanner", "", "Spanner database URI")

	// GCP KMS configs
	cmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of gcpkms://keyname")
	cmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset. Valid options are [gcp-kms://keyname]")
	cmd.Flags().Uint("gcp-kms-retries", 0, "number of retries for GCP KMS requests")
	cmd.Flags().Uint32("gcp-kms-timeout", 0, "sets the RPC timeout per call for GCP KMS requests in seconds, defaults to 0 (no timeout)")
}

func (g *GCPBackend) GetKMSSignerOptions() ([]signerverifier.Option, error) {
	kmshash := viper.GetString("signer-kmshash")
	hashAlg, ok := hashAlgMap[kmshash]
	if !ok {
		return nil, fmt.Errorf("invalid hash algorithm for --signer-kmshash: %s", kmshash)
	}
	// initialize optional RPC options for GCP KMS
	rpcOpts := make([]signature.RPCOption, 0)
	callOpts := []grpc_retry.CallOption{grpc_retry.WithMax(viper.GetUint("gcp-kms-retries")), grpc_retry.WithPerRetryTimeout(time.Duration(viper.GetUint32("gcp-kms-timeout")) * time.Second)}
	rpcOpts = append(rpcOpts, gcp.WithGoogleAPIClientOption(option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))))

	return []signerverifier.Option{signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg, rpcOpts)}, nil
}

func (g *GCPBackend) GetDriverConfig() (tessera.DriverConfiguration, error) {
	return tessera.DriverConfiguration{
		Hostname:            viper.GetString("hostname"),
		GCPBucket:           viper.GetString("gcp-bucket"),
		GCPSpannerDB:        viper.GetString("gcp-spanner"),
		PersistentAntispam:  viper.GetBool("persistent-antispam"),
		ASMaxBatchSize:      viper.GetUint("antispam-max-batch-size"),
		ASPushbackThreshold: viper.GetUint("antispam-pushback-threshold"),
	}, nil
}

var hashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

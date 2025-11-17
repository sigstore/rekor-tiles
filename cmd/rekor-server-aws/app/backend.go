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

	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
)

// AWSBackend implements the BackendConfig interface for AWS
type AWSBackend struct{}

func (a *AWSBackend) Name() string {
	return "aws"
}

func (a *AWSBackend) Description() string {
	return "Amazon Web Services"
}

func (a *AWSBackend) SetupLogger(logLevel slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
}

func (a *AWSBackend) RegisterFlags(cmd *cobra.Command) {
	// AWS-specific storage configs
	cmd.Flags().String("aws-bucket", "", "S3 bucket for tile and checkpoint storage")
	cmd.Flags().String("aws-mysql-dsn", "", "MySQL DSN for Aurora/RDS (e.g., user:pass@tcp(host:3306)/dbname)")

	// AWS KMS configs
	cmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of awskms://keyname")
	cmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset. Valid options are [aws-kms://keyname]")
}

func (a *AWSBackend) GetKMSSignerOptions() ([]signerverifier.Option, error) {
	kmshash := viper.GetString("signer-kmshash")
	hashAlg, ok := hashAlgMap[kmshash]
	if !ok {
		return nil, fmt.Errorf("invalid hash algorithm for --signer-kmshash: %s", kmshash)
	}
	// AWS KMS doesn't need the same RPC options as GCP
	return []signerverifier.Option{signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg, nil)}, nil
}

func (a *AWSBackend) GetDriverConfig() (tessera.DriverConfiguration, error) {
	return tessera.DriverConfiguration{
		Hostname:            viper.GetString("hostname"),
		AWSBucket:           viper.GetString("aws-bucket"),
		AWSMySQLDSN:         viper.GetString("aws-mysql-dsn"),
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

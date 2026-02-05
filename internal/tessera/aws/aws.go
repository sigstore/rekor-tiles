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

package aws

import (
	"context"
	"fmt"
	"net/http"

	awssdk "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/aws"
	antispam "github.com/transparency-dev/tessera/storage/aws/antispam"
)

// DriverConfiguration contains storage-specific configuration for the AWS storage backend.
type DriverConfiguration struct {
	// AWS configuration
	AWSBucket    string
	AWSMySQLDSN  string
	MaxOpenConns int
	MaxIdleConns int

	// Antispam configuration
	PersistentAntispam  bool
	ASMaxBatchSize      uint
	ASPushbackThreshold uint
}

// NewDriver creates a Tessera driver and optional persistent antispam for AWS storage backend.
func NewDriver(ctx context.Context, config DriverConfiguration) (tessera.Driver, tessera.Antispam, error) {
	if config.AWSBucket == "" || config.AWSMySQLDSN == "" {
		return nil, nil, fmt.Errorf("AWS backend requires --aws-bucket and --aws-mysql-dsn flags")
	}

	driver, err := newAWSDriver(ctx, config.AWSBucket, config.AWSMySQLDSN, config.MaxOpenConns, config.MaxIdleConns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize AWS driver: %v", err.Error())
	}
	var persistentAntispam tessera.Antispam
	if config.PersistentAntispam {
		as, err := newAWSAntispam(ctx, config.AWSMySQLDSN, config.ASMaxBatchSize, config.ASPushbackThreshold)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize AWS antispam: %v", err.Error())
		}
		persistentAntispam = as
	}
	return driver, persistentAntispam, nil
}

// newAWSDriver returns an AWS Tessera Driver for the given S3 bucket and MySQL DSN.
func newAWSDriver(ctx context.Context, bucket, mysqlDSN string, maxOpenConns, maxIdleConns int) (tessera.Driver, error) {
	// Load AWS SDK configuration from environment
	sdkCfg, err := awssdk.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS SDK config: %w", err)
	}

	// Configure S3 client options to use path-style addressing for MinIO compatibility
	s3Opts := func(o *s3.Options) {
		o.UsePathStyle = true
	}

	cfg := aws.Config{
		SDKConfig:  &sdkCfg,
		S3Options:  s3Opts,
		Bucket:     bucket,
		DSN:        mysqlDSN,
		HTTPClient: http.DefaultClient,
	}
	if maxOpenConns > 0 {
		cfg.MaxOpenConns = maxOpenConns
	}
	if maxIdleConns > 0 {
		cfg.MaxIdleConns = maxIdleConns
	}

	driver, err := aws.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting tessera AWS driver: %w", err)
	}
	return driver, nil
}

// newAWSAntispam initializes a MySQL database to store recent entries for deduplication.
func newAWSAntispam(ctx context.Context, mysqlDSN string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := antispam.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	return antispam.NewAntispam(ctx, mysqlDSN, asOpts)
}

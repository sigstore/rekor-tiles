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

package tessera

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/aws"
	antispam "github.com/transparency-dev/tessera/storage/aws/antispam"
)

// NewAWSDriver returns an AWS Tessera Driver for the given S3 bucket and MySQL DSN.
func NewAWSDriver(ctx context.Context, bucket, mysqlDSN, _ string) (tessera.Driver, error) {
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
		SDKConfig: &sdkCfg,
		S3Options: s3Opts,
		Bucket:    bucket,
		DSN:       mysqlDSN,
	}
	driver, err := aws.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting tessera AWS driver: %w", err)
	}
	return driver, nil
}

// NewAWSAntispam initializes a MySQL database to store recent entries for deduplication
func NewAWSAntispam(ctx context.Context, mysqlDSN string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := antispam.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	return antispam.NewAntispam(ctx, mysqlDSN, asOpts)
}

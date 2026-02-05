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

package gcpcloudsql

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awssdk "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/transparency-dev/tessera"
	cloudsql "github.com/transparency-dev/tessera/storage/aws"
	antispam "github.com/transparency-dev/tessera/storage/aws/antispam"
)

// DriverConfiguration contains storage-specific configuration for the GCP CloudSQL storage backend
type DriverConfiguration struct {
	// GCP Cloud SQL + GCS configuration
	GCPCloudSQLDSN string
	GCPBucket      string
	MaxOpenConns   int
	MaxIdleConns   int

	// Antispam configuration
	PersistentAntispam  bool
	ASMaxBatchSize      uint
	ASPushbackThreshold uint
}

// NewDriver creates a Tessera driver and optional persistent antispam for a GCP CloudSQL storage backend
func NewDriver(ctx context.Context, config DriverConfiguration) (tessera.Driver, tessera.Antispam, error) {
	if config.GCPCloudSQLDSN == "" || config.GCPBucket == "" {
		return nil, nil, fmt.Errorf("GCP CloudSQL backend requires --gcp-bucket and --gcp-cloudsql-dsn flags")
	}

	driver, err := newCloudSQLDriver(ctx, config.GCPCloudSQLDSN, config.GCPBucket, config.MaxOpenConns, config.MaxIdleConns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize GCP CloudSQL driver: %v", err.Error())
	}
	var persistentAntispam tessera.Antispam
	if config.PersistentAntispam {
		as, err := newCloudSQLAntispam(ctx, config.GCPCloudSQLDSN, config.ASMaxBatchSize, config.ASPushbackThreshold)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize GCP CloudSQL antispam: %v", err.Error())
		}
		persistentAntispam = as
	}
	return driver, persistentAntispam, nil
}

// newCloudSQLDriver returns a GCP Tessera Driver for the given Cloud Storage bucket and CloudSQL DSN.
func newCloudSQLDriver(ctx context.Context, cloudSQLDSN, bucket string, maxOpenConns, maxIdleConns int) (tessera.Driver, error) {
	// Load AWS SDK configuration from environment
	sdkCfg, err := awssdk.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS SDK config: %w", err)
	}

	accessKey := os.Getenv("GCS_HMAC_ACCESS_KEY_ID")
	secret := os.Getenv("GCS_HMAC_SECRET")
	region := os.Getenv("GCS_REGION")
	if region == "" {
		region = "auto"
	}
	endpoint := os.Getenv("GCS_ENDPOINT_URL")
	sdkCfg, err = awssdk.LoadDefaultConfig(ctx,
		awssdk.WithRegion(region),
		awssdk.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey,
			secret,
			"",
		)),
		awssdk.WithBaseEndpoint(endpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS SDK config for GCS: %w", err)
	}

	// Workaround for GCS support from https://github.com/aws/aws-sdk-go-v2/issues/1816#issuecomment-1927281540
	// and https://github.com/fleetdm/fleet/pull/32573
	s3Opts := func(o *s3.Options) {
		o.UsePathStyle = true
		// GCS alters the Accept-Encoding header which breaks the request signature
		ignoreSigningHeaders(o, []string{"Accept-Encoding"})
		// GCS also has issues with trailing checksums in UploadPart and PutObject operations
		disableTrailingChecksumForGCS(o)
	}

	cfg := cloudsql.Config{
		SDKConfig:  &sdkCfg,
		S3Options:  s3Opts,
		Bucket:     bucket,
		DSN:        cloudSQLDSN,
		HTTPClient: http.DefaultClient,
	}
	if maxOpenConns > 0 {
		cfg.MaxOpenConns = maxOpenConns
	}
	if maxIdleConns > 0 {
		cfg.MaxIdleConns = maxIdleConns
	}

	driver, err := cloudsql.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting Tessera GCP Cloud SQL driver: %w", err)
	}
	return driver, nil
}

// newCloudSQLAntispam initializes a GCP CloudSQL database to store recent entries for deduplication.
func newCloudSQLAntispam(ctx context.Context, cloudsqlDSN string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := antispam.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	return antispam.NewAntispam(ctx, cloudsqlDSN, asOpts)
}

// GCS workaround middleware functions to fix signature issues
// See https://github.com/aws/aws-sdk-go-v2/issues/1816#issuecomment-1927281540
// and https://github.com/fleetdm/fleet/pull/32573

type ignoredHeadersKey struct{}

// ignoreSigningHeaders excludes the listed headers from the request signature
// because some providers (like GCS) may alter them, causing signature mismatches.
func ignoreSigningHeaders(o *s3.Options, headers []string) {
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		if err := stack.Finalize.Insert(ignoreHeaders(headers), "Signing", middleware.Before); err != nil {
			return err
		}

		if err := stack.Finalize.Insert(restoreIgnored(), "Signing", middleware.After); err != nil {
			return err
		}

		return nil
	})
}

func ignoreHeaders(headers []string) middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"IgnoreHeaders",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(ignoreHeaders) unexpected request middleware type %T", in.Request)}
			}

			ignored := make(map[string]string, len(headers))
			for _, h := range headers {
				ignored[h] = req.Header.Get(h)
				req.Header.Del(h)
			}

			ctx = middleware.WithStackValue(ctx, ignoredHeadersKey{}, ignored)

			return next.HandleFinalize(ctx, in)
		},
	)
}

func restoreIgnored() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"RestoreIgnored",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(restoreIgnored) unexpected request middleware type %T", in.Request)}
			}

			ignored, _ := middleware.GetStackValue(ctx, ignoredHeadersKey{}).(map[string]string)
			for k, v := range ignored {
				req.Header.Set(k, v)
			}

			return next.HandleFinalize(ctx, in)
		},
	)
}

// disableTrailingChecksumForGCS disables trailing checksums for UploadPart and PutObject operations using reflection
// This is part of the GCS compatibility workaround as GCS doesn't support trailing checksums
func disableTrailingChecksumForGCS(o *s3.Options) {
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc(
			"DisableTrailingChecksum",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (out middleware.InitializeOutput, metadata middleware.Metadata, err error) {
				// Check if this is an UploadPart or PutObject operation
				if opName := middleware.GetOperationName(ctx); opName == "UploadPart" || opName == "PutObject" {
					// Use reflection to disable trailing checksums in the checksum middleware
					// This is a hack, but it's the only way to disable trailing checksums currently
					if checksumMiddleware, ok := stack.Finalize.Get("AWSChecksum:ComputeInputPayloadChecksum"); ok {
						if v := reflect.ValueOf(checksumMiddleware).Elem(); v.IsValid() {
							if field := v.FieldByName("EnableTrailingChecksum"); field.IsValid() && field.CanSet() && field.Kind() == reflect.Bool {
								field.SetBool(false)
							}
						}
					}
					// Remove the trailing checksum middleware entirely
					_, _ = stack.Finalize.Remove("addInputChecksumTrailer")
				}
				return next.HandleInitialize(ctx, in)
			},
		), middleware.Before)
	})
}

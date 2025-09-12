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
	"runtime"

	"cloud.google.com/go/spanner"
	gcs "cloud.google.com/go/storage"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/gcp"
	antispam "github.com/transparency-dev/tessera/storage/gcp/antispam"
	"google.golang.org/api/option"
	"sigs.k8s.io/release-utils/version"
)

// NewGCPDriver returns a GCP Tessera Driver for the given bucket and spanner URI.
func NewGCPDriver(ctx context.Context, bucket, spannerDB, hostname string) (tessera.Driver, error) {
	userAgent := userAgent(hostname)
	gcsClient, err := gcs.NewClient(ctx, gcs.WithJSONReads(), option.WithUserAgent(userAgent))
	if err != nil {
		return nil, fmt.Errorf("creating storage client: %w", err)
	}
	spannerClient, err := spanner.NewClient(ctx, spannerDB, option.WithUserAgent(userAgent))
	if err != nil {
		return nil, fmt.Errorf("creating spanner client: %w", err)
	}
	cfg := gcp.Config{
		Bucket:        bucket,
		Spanner:       spannerDB,
		GCSClient:     gcsClient,
		SpannerClient: spannerClient,
	}
	driver, err := gcp.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting tessera GCP driver: %w", err)
	}
	return driver, nil
}

// NewGCPAntispam initializes a Spanner database to store recent entries
func NewGCPAntispam(ctx context.Context, spannerDb string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := antispam.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	dbName := fmt.Sprintf("%s-antispam", spannerDb)
	return antispam.NewAntispam(ctx, dbName, asOpts)
}

func userAgent(hostname string) string {
	return fmt.Sprintf("rekor-tiles/%s (%s; %s) %s", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH, hostname)
}

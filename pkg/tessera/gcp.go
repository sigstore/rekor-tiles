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

	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/storage/gcp"
)

// NewGCPDriver returns a GCP Tessera Driver for the given bucket and spanner URI.
func NewGCPDriver(ctx context.Context, bucket, spanner string) (tessera.Driver, error) {
	cfg := gcp.Config{
		Bucket:  bucket,
		Spanner: spanner,
	}
	driver, err := gcp.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("getting tessera GCP driver: %w", err)
	}
	return driver, nil
}

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

package posix

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	badger_as "github.com/transparency-dev/tessera/storage/posix/antispam"
)

// DriverConfiguration contains storage-specific configuration for the POSIX storage backend.
type DriverConfiguration struct {
	// POSIX configuration
	StorageDir string

	// Antispam configuration
	PersistentAntispam  bool
	ASMaxBatchSize      uint
	ASPushbackThreshold uint
}

// NewDriver creates a Tessera driver and optional persistent antispam for the POSIX backend.
func NewDriver(ctx context.Context, config DriverConfiguration) (tessera.Driver, tessera.Antispam, error) {
	driver, err := newPOSIXDriver(ctx, config.StorageDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize POSIX driver: %v", err.Error())
	}

	var persistentAntispam tessera.Antispam
	if config.PersistentAntispam {
		as, err := newPOSIXAntispam(ctx, config.StorageDir, config.ASMaxBatchSize, config.ASPushbackThreshold)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize GCP antispam: %v", err.Error())
		}
		persistentAntispam = as
	}

	return driver, persistentAntispam, nil
}

// newPOSIXDriver returns a POSIX Tessera Driver for the given storage directory.
func newPOSIXDriver(ctx context.Context, storageDir string) (tessera.Driver, error) {
	driver, err := posix.New(ctx, posix.Config{Path: storageDir})
	if err != nil {
		return nil, fmt.Errorf("creating Tessera POSIX driver: %w", err)
	}
	return driver, nil
}

// newPOSIXAntispam initializes a key-value database to store recent entries
func newPOSIXAntispam(ctx context.Context, storageDir string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := badger_as.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	return badger_as.NewAntispam(ctx, filepath.Join(storageDir, ".state", "antispam"), asOpts)
}

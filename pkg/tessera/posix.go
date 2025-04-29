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
	"path/filepath"

	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/storage/posix"
	badger_as "github.com/transparency-dev/trillian-tessera/storage/posix/antispam"
)

// NewPOSIXDriver returns a POSIX Tessera Driver for the given storage directory.
func NewPOSIXDriver(ctx context.Context, storageDir string) (tessera.Driver, error) {
	driver, err := posix.New(ctx, storageDir)
	if err != nil {
		return nil, fmt.Errorf("creating Tessera POSIX driver: %w", err)
	}
	return driver, nil
}

// Antispam initializes a key-value database to store recent entries
func NewPOSIXAntispam(ctx context.Context, storageDir string, maxBatchSize, pushbackThreshold uint) (tessera.Antispam, error) {
	asOpts := badger_as.AntispamOpts{
		MaxBatchSize:      maxBatchSize,
		PushbackThreshold: pushbackThreshold,
	}
	return badger_as.NewAntispam(ctx, filepath.Join(storageDir, ".state", "antispam"), asOpts)
}

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
	"log/slog"

	rekorapp "github.com/sigstore/rekor-tiles/v2/internal/rekor/app"
	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/spf13/cobra"
)

// BackendConfig defines the interface for backend-specific configuration.
// Each storage backend (AWS, GCP) implements this interface to customize
// server behavior for their specific cloud provider.
type BackendConfig interface {
	// Name returns the backend name (e.g., "aws", "gcp")
	Name() string

	// Description returns a description of the backend
	Description() string

	// SetupLogger configures and returns the logger for this backend
	SetupLogger(logLevel slog.Level) *slog.Logger

	// RegisterFlags registers backend-specific flags with the serve command
	RegisterFlags(cmd *cobra.Command)

	// GetKMSSignerOptions returns the KMS signer configuration for this backend
	GetKMSSignerOptions() ([]signerverifier.Option, error)

	// GetDriverConfig returns the tessera driver configuration for this backend
	GetDriverConfig() (tessera.DriverConfiguration, error)
}

// SetBackendKMSSignerOptions sets the global KMS signer options function
// based on the provided backend configuration
func SetBackendKMSSignerOptions(backend BackendConfig) {
	rekorapp.GetKMSSignerOptions = backend.GetKMSSignerOptions
}

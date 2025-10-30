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

package main

import (
	"os"
	"testing"
)

// BackendConfig holds configuration for a specific storage backend
type BackendConfig struct {
	Name         string
	StorageURL   string
	RekorURL     string
	Hostname     string
	ServerPubKey string
}

// GetBackendConfigs returns the list of backend configurations to test
func GetBackendConfigs(_ *testing.T) []BackendConfig {
	configs := []BackendConfig{
		{
			Name:         "GCP",
			StorageURL:   "http://localhost:7080/tiles",
			RekorURL:     "http://localhost:3003",
			Hostname:     "rekor-local",
			ServerPubKey: "./testdata/pki/ed25519-pub-key.pem",
		},
	}

	// Add AWS backend if environment variable is set
	if os.Getenv("TEST_AWS_BACKEND") == "true" {
		configs = append(configs, BackendConfig{
			Name:         "AWS",
			StorageURL:   "http://localhost:9000/tiles", // MinIO default port
			RekorURL:     "http://localhost:3004",       // Different port from GCP
			Hostname:     "rekor-local-aws",
			ServerPubKey: "./testdata/pki/ed25519-pub-key.pem",
		})
	}

	return configs
}

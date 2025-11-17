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

//go:build e2e

package main

import (
	"os"
	"strings"
	"testing"
)

// BackendConfig holds configuration for a specific storage backend
type BackendConfig struct {
	Name         string
	StorageURL   string
	RekorURL     string
	Hostname     string
	ServerPubKey string
	ComposeFile  string // Path to docker compose file for this backend
}

// GetBackendConfigs returns the list of backend configurations to test
// The TEST_BACKENDS environment variable controls which backends to test:
//   - "gcp" (default): test only GCP backend
//   - "aws": test only AWS backend
//   - "gcp,aws" or "all": test both backends
func GetBackendConfigs(_ *testing.T) []BackendConfig {
	// Get requested backends from environment variable
	backendsEnv := os.Getenv("TEST_BACKENDS")
	if backendsEnv == "" {
		backendsEnv = "gcp" // default to GCP only
	}

	// Parse comma-separated list
	requestedBackends := make(map[string]bool)
	if backendsEnv == "all" {
		requestedBackends["gcp"] = true
		requestedBackends["aws"] = true
	} else {
		for _, backend := range strings.Split(backendsEnv, ",") {
			backend = strings.TrimSpace(strings.ToLower(backend))
			if backend != "" {
				requestedBackends[backend] = true
			}
		}
	}

	// Build list of backend configs
	var configs []BackendConfig

	if requestedBackends["gcp"] {
		configs = append(configs, BackendConfig{
			Name:         "GCP",
			StorageURL:   "http://localhost:7080/tiles",
			RekorURL:     "http://localhost:3003",
			Hostname:     "rekor-local",
			ServerPubKey: "./testdata/pki/ed25519-pub-key.pem",
			ComposeFile:  "compose.yml",
		})
	}

	if requestedBackends["aws"] {
		configs = append(configs, BackendConfig{
			Name:         "AWS",
			StorageURL:   "http://localhost:9000/tiles", // MinIO default port
			RekorURL:     "http://localhost:3004",       // Different port from GCP
			Hostname:     "rekor-local-aws",
			ServerPubKey: "./testdata/pki/ed25519-pub-key.pem",
			ComposeFile:  "docker-compose-aws.yml",
		})
	}

	return configs
}

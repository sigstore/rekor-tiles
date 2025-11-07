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

//go:build e2e && freeze

package main

import (
	"context"
	"testing"

	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/write"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"go.step.sm/crypto/pemutil"
)

func setupFreeze(t *testing.T, backend BackendConfig) (read.Client, write.Client, signature.Verifier, error) {
	t.Helper()

	serverPubKey, err := pemutil.Read(backend.ServerPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// reader client
	reader, err := read.NewReader(backend.StorageURL, backend.Hostname, verifier)
	if err != nil {
		return nil, nil, nil, err
	}

	// writer client
	writer, err := write.NewWriter(backend.RekorURL)
	if err != nil {
		return nil, nil, nil, err
	}
	return reader, writer, verifier, nil
}

func TestPreFreeze(t *testing.T) {
	ctx := context.Background()
	backends := GetBackendConfigs(t)

	for _, backend := range backends {
		t.Run(backend.Name, func(t *testing.T) {
			reader, writer, _, err := setupFreeze(t, backend)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, note, err := reader.ReadCheckpoint(ctx)
			if err != nil {
				t.Fatalf("Failed to read checkpoint (is docker compose running?): %v", err)
			}
			assert.NotNil(t, checkpoint)
			assert.NotNil(t, note)
			if note != nil {
				assert.NotContains(t, string(note.Text), "Log frozen —")
			}

			clientPrivKey, clientPubKey, err := genKeys()
			if err != nil {
				t.Fatal(err)
			}
			hr, err := newHashedRekordRequest(clientPrivKey, clientPubKey, 1)
			if err != nil {
				t.Fatal(err)
			}
			_, err = writer.Add(ctx, hr)
			assert.NoError(t, err)
		})
	}
}

func TestPostFreeze(t *testing.T) {
	ctx := context.Background()
	backends := GetBackendConfigs(t)

	for _, backend := range backends {
		t.Run(backend.Name, func(t *testing.T) {
			reader, writer, _, err := setupFreeze(t, backend)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, note, err := reader.ReadCheckpoint(ctx)
			if err != nil {
				t.Fatalf("Failed to read checkpoint (is docker compose running?): %v", err)
			}
			assert.NotNil(t, checkpoint)
			assert.NotNil(t, note)
			if note != nil {
				assert.Contains(t, string(note.Text), "Log frozen —")
			}

			clientPrivKey, clientPubKey, err := genKeys()
			if err != nil {
				t.Fatal(err)
			}
			hr, err := newHashedRekordRequest(clientPrivKey, clientPubKey, 1)
			if err != nil {
				t.Fatal(err)
			}
			tle, err := writer.Add(ctx, hr)
			assert.Nil(t, tle)
			assert.Error(t, err)
			if err != nil {
				assert.Contains(t, err.Error(), "unexpected response: 405 This log has been frozen, please switch to the latest log.")
			}
		})
	}
}

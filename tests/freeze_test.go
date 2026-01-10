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

	"github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/write"
	"github.com/stretchr/testify/assert"
)

const (
	defaultServerPrivateKey = "./testdata/pki/ed25519-priv-key.pem"
)

func TestGCPPreFreeze(t *testing.T) {
	testPreFreeze(t, gcpConfig)
}

func TestGCPPostFreeze(t *testing.T) {
	testPostFreeze(t, gcpConfig)
}

func setup(config backendConfig) (read.Client, write.Client, error) {
	// get verifier needed for both read and write
	verifier, err := signerverifier.NewFileSignerVerifier(defaultServerPrivateKey, "")
	if err != nil {
		return nil, nil, err
	}

	// reader client
	reader, err := read.NewReader(config.StorageURL, defaultRekorHostname, verifier)
	if err != nil {
		return nil, nil, err
	}

	// writer client
	writer, err := write.NewWriter(config.ServerURL)
	if err != nil {
		return nil, nil, err
	}
	return reader, writer, nil
}

func testPreFreeze(t *testing.T, config backendConfig) {
	ctx := context.Background()
	reader, writer, err := setup(config)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, note, err := reader.ReadCheckpoint(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, checkpoint)
	assert.NotNil(t, note)
	assert.NotContains(t, string(note.Text), "Log frozen —")

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
}

func testPostFreeze(t *testing.T, config backendConfig) {
	ctx := context.Background()
	reader, writer, err := setup(config)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, note, err := reader.ReadCheckpoint(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, checkpoint)
	assert.NotNil(t, note)
	assert.Contains(t, string(note.Text), "Log frozen —")

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
	assert.Contains(t, err.Error(), "unexpected response: 405 This log has been frozen, please switch to the latest log.")
}

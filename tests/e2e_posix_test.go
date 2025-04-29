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

//go:build e2e && posix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/sigstore/rekor-tiles/pkg/client/read"
	"github.com/sigstore/rekor-tiles/pkg/client/write"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/trillian-tessera/api"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestPOSIXReadWrite(t *testing.T) {
	ctx := context.Background()

	// get verifier needed for both read and write
	serverPubKey, err := pemutil.Read(defaultServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// reader client
	reader, err := read.NewReader(defaultRekorReadURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	// writer client
	writer, err := write.NewWriter(defaultRekorURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	// Get the current checkpoint
	checkpoint, note, err := reader.ReadCheckpoint(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, checkpoint)
	assert.NotNil(t, note)
	initialTreeSize := checkpoint.Size

	clientPrivKey, clientPubKey, err := genKeys()
	if err != nil {
		t.Fatal(err)
	}
	// Add new entries - more than one tile's worth
	numNewEntries := uint64(260)
	group := new(errgroup.Group)
	// Limit number of concurrent requests, as e2e tests fail on macOS
	// without a reasonable limit set
	group.SetLimit(50)
	for i := uint64(1); i <= numNewEntries; i++ {
		i := i
		group.Go(func() error {
			hr, err := newHashedRekordRequest(clientPrivKey, clientPubKey, i)
			if err != nil {
				return err
			}
			_, err = writer.Add(ctx, hr) // We don't need to check the TLE here, the client verifies the inclusion proof for us
			assert.NoError(t, err)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
	// Add one more entry outside of the errgroup so we know it's the last one.
	numNewEntries++
	hr, err := newHashedRekordRequest(clientPrivKey, clientPubKey, numNewEntries)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Add(ctx, hr)
	assert.NoError(t, err)

	// Check the checkpoint again
	checkpoint, note, err = reader.ReadCheckpoint(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, checkpoint)
	assert.NotNil(t, note)
	latestTreeSize := checkpoint.Size
	assert.GreaterOrEqual(t, latestTreeSize, initialTreeSize+numNewEntries)

	// Get the first tile, this should be full as long as more than 256 entries have been added.
	tileLevel := uint64(0)
	tileIndex := uint64(0)
	tilePart := uint8(0)
	firstTileBytes, err := reader.ReadTile(ctx, tileLevel, tileIndex, tilePart)
	assert.NoError(t, err)
	assert.NotEmpty(t, firstTileBytes)
	entryBundle, err := reader.ReadEntryBundle(ctx, tileIndex, tilePart)
	assert.NoError(t, err)
	assert.NotEmpty(t, entryBundle)

	// Get the latest tile on the lowest level. Since we added >256 entries, this index should be at least 1.
	tileIndex = latestTreeSize / layout.TileWidth
	assert.GreaterOrEqual(t, tileIndex, uint64(1))
	tilePart = layout.PartialTileSize(tileLevel, latestTreeSize-1, latestTreeSize)
	lastTileBytes, err := reader.ReadTile(ctx, tileLevel, tileIndex, tilePart)
	assert.NoError(t, err)
	assert.NotEmpty(t, lastTileBytes)
	assert.NotEqual(t, firstTileBytes, lastTileBytes)
	entryBundle, err = reader.ReadEntryBundle(ctx, tileIndex, tilePart)
	assert.NoError(t, err)
	assert.Contains(t, string(entryBundle), base64.StdEncoding.EncodeToString(artifactDigest(numNewEntries)))

	// Add a DSSE entry
	dr, err := newDSSERequest(clientPrivKey, clientPubKey)
	if err != nil {
		t.Fatal(err)
	}
	tle, err := writer.Add(ctx, dr)
	assert.NoError(t, err)

	safeLogSize, err := tessera.NewSafeInt64(tle.InclusionProof.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	latestTreeSize = safeLogSize.U()
	tileIndex = latestTreeSize / layout.TileWidth
	tilePart = layout.PartialTileSize(tileLevel, latestTreeSize-1, latestTreeSize)
	entryBundle, err = reader.ReadEntryBundle(ctx, tileIndex, tilePart)
	assert.NoError(t, err)
	expectedPayloadHash := sha256.Sum256([]byte("payload"))
	expectedB64PayloadHash := base64.StdEncoding.EncodeToString(expectedPayloadHash[:])
	assert.Contains(t, string(entryBundle), expectedB64PayloadHash)

	// Add a second identical entry immediately to check for deduplication
	oldIndex := tle.LogIndex
	_, err = writer.Add(ctx, dr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected response: 409")
	assert.ErrorContains(t, err, fmt.Sprintf("an equivalent entry already exists in the transparency log with index %d", oldIndex))
}

// Must only be run after TestPOSIXReadWrite with a persistent volume mounted to the container
func TestPOSIXPersistentAnitspam(t *testing.T) {
	ctx := context.Background()

	// initialize verifier for reader
	serverPubKey, err := pemutil.Read(defaultServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// write and read clients
	writer, err := write.NewWriter(defaultRekorURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := read.NewReader(defaultRekorReadURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	// fetch and parse an entry bundle
	entryBundle, err := reader.ReadEntryBundle(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle := api.EntryBundle{}
	err = bundle.UnmarshalText(entryBundle)
	assert.NoError(t, err)
	assert.NotEmpty(t, bundle.Entries)

	// transform existing entry to request to upload again
	hr := &pb.HashedRekordLogEntryV0_0_2{}
	err = protojson.Unmarshal(bundle.Entries[0], hr)
	assert.NoError(t, err)
	hrRequest := &pb.HashedRekordRequestV0_0_2{}
	hrRequest.Digest = hr.Data.Digest
	hrRequest.Signature = hr.Signature

	_, err = writer.Add(ctx, hrRequest)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected response: 409")
}

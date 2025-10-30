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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/write"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"go.step.sm/crypto/pemutil"
	signednote "golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultServerPublicKey = "./testdata/pki/ed25519-pub-key.pem"
	// Legacy constants for tests that haven't been refactored yet
	defaultRekorURL      = "http://localhost:3003"
	defaultRekorHostname = "rekor-local"
)

// backendClients holds the clients and verifiers for a specific backend
type backendClients struct {
	reader       read.Client
	writer       write.Client
	verifier     signature.Verifier
	noteVerifier signednote.Verifier
	logID        []byte
}

// setupBackendClients initializes all clients for a given backend configuration
func setupBackendClients(t *testing.T, backend BackendConfig) *backendClients {
	t.Helper()

	serverPubKey, err := pemutil.Read(backend.ServerPubKey)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		t.Fatal(err)
	}

	noteVerifier, err := note.NewNoteVerifier(backend.Hostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := read.NewReader(backend.StorageURL, backend.Hostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	writer, err := write.NewWriter(backend.RekorURL)
	if err != nil {
		t.Fatal(err)
	}

	_, logID, err := note.KeyHash(backend.Hostname, serverPubKey)
	if err != nil {
		t.Fatal(err)
	}

	return &backendClients{
		reader:       reader,
		writer:       writer,
		verifier:     verifier,
		noteVerifier: noteVerifier,
		logID:        logID,
	}
}

func TestReadWrite(t *testing.T) {
	ctx := context.Background()
	backends := GetBackendConfigs(t)

	for _, backend := range backends {
		backend := backend // capture loop variable
		t.Run(backend.Name, func(t *testing.T) {
			clients := setupBackendClients(t, backend)

			// Get the current checkpoint
			checkpoint, note, err := clients.reader.ReadCheckpoint(ctx)
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
					tle, err := clients.writer.Add(ctx, hr)
					assert.NoError(t, err)
					assertHashedRekordTLE(t, tle, initialTreeSize, numNewEntries, clients.logID, clients.noteVerifier, hr)
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
			tle, err := clients.writer.Add(ctx, hr)
			assert.NoError(t, err)
			assertHashedRekordTLE(t, tle, initialTreeSize, numNewEntries, clients.logID, clients.noteVerifier, hr)

			// Check the checkpoint again
			checkpoint, note, err = clients.reader.ReadCheckpoint(ctx)
			assert.NoError(t, err)
			assert.NotNil(t, checkpoint)
			assert.NotNil(t, note)
			latestTreeSize := checkpoint.Size
			assert.GreaterOrEqual(t, latestTreeSize, initialTreeSize+numNewEntries)

			// Get the first tile, this should be full as long as more than 256 entries have been added.
			tileLevel := uint64(0)
			tileIndex := uint64(0)
			tilePart := uint8(0)
			firstTileBytes, err := clients.reader.ReadTile(ctx, tileLevel, tileIndex, tilePart)
			assert.NoError(t, err)
			assert.NotEmpty(t, firstTileBytes)
			entryBundle, err := clients.reader.ReadEntryBundle(ctx, tileIndex, tilePart)
			assert.NoError(t, err)
			assert.NotEmpty(t, entryBundle)

			// Get the latest tile on the lowest level. Since we added >256 entries, this index should be at least 1.
			tileIndex = latestTreeSize / layout.TileWidth
			assert.GreaterOrEqual(t, tileIndex, uint64(1))
			tilePart = layout.PartialTileSize(tileLevel, latestTreeSize-1, latestTreeSize)
			lastTileBytes, err := clients.reader.ReadTile(ctx, tileLevel, tileIndex, tilePart)
			assert.NoError(t, err)
			assert.NotEmpty(t, lastTileBytes)
			assert.NotEqual(t, firstTileBytes, lastTileBytes)
			entryBundle, err = clients.reader.ReadEntryBundle(ctx, tileIndex, tilePart)
			assert.NoError(t, err)
			assert.Contains(t, string(entryBundle), base64.StdEncoding.EncodeToString(artifactDigest(numNewEntries)))

			// Parse a HashedRekord entry from the latest entry bundle
			bundle := api.EntryBundle{}
			err = bundle.UnmarshalText(entryBundle)
			assert.NoError(t, err)
			assert.NotEmpty(t, bundle.Entries)
			e := &pb.Entry{}
			err = protojson.Unmarshal(bundle.Entries[0], e)
			assert.NoError(t, err)
			assert.Equal(t, "hashedrekord", e.Kind)
			assert.Equal(t, "0.0.2", e.ApiVersion)
			hrEntry := e.Spec.GetHashedRekordV002()
			assert.NotNil(t, hrEntry)

			// Add a DSSE entry
			numNewEntries++
			dr, err := newDSSERequest(clientPrivKey, clientPubKey)
			if err != nil {
				t.Fatal(err)
			}
			tle, err = clients.writer.Add(ctx, dr)
			assert.NoError(t, err)
			assertDSSETLE(t, tle, initialTreeSize+numNewEntries-1, clients.logID, clients.noteVerifier, dr)

			safeLogSize, err := tessera.NewSafeInt64(tle.InclusionProof.TreeSize)
			if err != nil {
				t.Fatal(err)
			}
			latestTreeSize = safeLogSize.U()
			tileIndex = latestTreeSize / layout.TileWidth
			tilePart = layout.PartialTileSize(tileLevel, latestTreeSize-1, latestTreeSize)
			entryBundle, err = clients.reader.ReadEntryBundle(ctx, tileIndex, tilePart)
			assert.NoError(t, err)
			expectedPayloadHash := sha256.Sum256([]byte("payload"))
			expectedB64PayloadHash := base64.StdEncoding.EncodeToString(expectedPayloadHash[:])
			assert.Contains(t, string(entryBundle), expectedB64PayloadHash)

			// Parse a DSSE entry from the latest entry bundle
			bundle = api.EntryBundle{}
			err = bundle.UnmarshalText(entryBundle)
			assert.NoError(t, err)
			assert.NotEmpty(t, bundle.Entries)
			e = &pb.Entry{}
			// last entry in the bundle should be a DSSE entry
			err = protojson.Unmarshal(bundle.Entries[len(bundle.Entries)-1], e)
			assert.NoError(t, err)
			assert.Equal(t, "dsse", e.Kind)
			assert.Equal(t, "0.0.2", e.ApiVersion)
			dsseEntry := e.Spec.GetDsseV002()
			assert.NotNil(t, dsseEntry)
		})
	}
}

func TestUnimplementedReadMethods(t *testing.T) {
	ctx := context.Background()

	serverPubKey, err := pemutil.Read(defaultServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := read.NewReader(defaultRekorURL+"/api/v2", defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadCheckpoint(ctx)
	assert.ErrorContains(t, err, "501") // the reader client drops the request body, hence why we only check the status code
	_, err = reader.ReadTile(ctx, 0, 0, 0)
	assert.ErrorContains(t, err, "501")
	_, err = reader.ReadEntryBundle(ctx, 0, 0)
	assert.ErrorContains(t, err, "501")
}

func TestPersistentDeduplication(t *testing.T) {
	ctx := context.Background()

	path, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("skipping persistent deduplication test because docker is not installed")
	}
	output, err := exec.Command(path, "compose", "ps", "rekor").Output()
	if err != nil || !strings.Contains(string(output), "rekor-tiles-rekor-1") {
		t.Skip("skipping persistent deduplication test because rekor-tiles is not running as a local docker container")
	}

	// writer client
	writer, err := write.NewWriter(defaultRekorURL)
	if err != nil {
		t.Fatal(err)
	}

	clientPrivKey, clientPubKey, err := genKeys()
	if err != nil {
		t.Fatal(err)
	}

	// add one entry
	hr, err := newHashedRekordRequest(clientPrivKey, clientPubKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Add(ctx, hr)
	assert.NoError(t, err)

	// add the same entry and check for in-memory deduplication
	_, err = writer.Add(ctx, hr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected response: 409")
	assert.ErrorContains(t, err, "an equivalent entry already exists in the transparency log with index")

	// restart rekor-tiles and check for persistent deduplication
	err = exec.Command(path, "compose", "restart", "rekor").Run()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 3; i++ {
		out, err := exec.Command(path, "compose", "ps", "rekor", "--format='{{print .Status}}'").Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "(healthy)") {
			break
		}
		if i == 3 {
			t.Fatal("docker container took too long to restart")
		}
		time.Sleep(1 * time.Second)
	}
	_, err = writer.Add(ctx, hr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected response: 409")
	assert.ErrorContains(t, err, "an equivalent entry already exists in the transparency log with index")
}

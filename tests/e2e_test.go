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
	"encoding/pem"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor-tiles/pkg/client"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"go.step.sm/crypto/pemutil"
)

const (
	defaultRekorURL      = "http://localhost:3000"
	defaultRekorHostname = "rekor-local"
	defaultGCSURL        = "http://127.0.0.1:7080/storage/v1/b/tiles/o"
	pubKey               = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p
2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END PUBLIC KEY-----
`
)

func TestAdd(t *testing.T) {
	ctx := context.Background()
	artifact := "artifact"
	digest := sha256.Sum256([]byte(artifact))
	sig, err := base64.StdEncoding.DecodeString("MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pubKey))
	req := &pb.HashedRekordRequest{
		Signature: sig,
		Data: &v1.HashOutput{
			Algorithm: v1.HashAlgorithm(v1.HashAlgorithm_SHA2_256),
			Digest:    digest[:],
		},
		Verifier: &pb.Verifier{
			Verifier: &pb.Verifier_PublicKey{
				PublicKey: &pb.PublicKey{
					RawBytes: block.Bytes,
				},
			},
		},
	}
	serverPubKey, err := pemutil.Read("./testdata/pki/ed25519-pub-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := client.NewWriter(defaultRekorURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}
	tle, err := writer.Add(ctx, req)
	assert.NoError(t, err)
	tileLevel := uint64(0)
	tileIndex, err := tessera.NewSafeInt64(tle.LogIndex / layout.TileWidth)
	if err != nil {
		t.Fatal(err)
	}
	logIndex, err := tessera.NewSafeInt64(tle.LogIndex)
	if err != nil {
		t.Fatal(err)
	}
	treeSize, err := tessera.NewSafeInt64(tle.InclusionProof.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	partialTileSize := layout.PartialTileSize(0, logIndex.U(), treeSize.U())
	reader, err := client.NewReader(defaultGCSURL, defaultRekorHostname, verifier)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, note, err := reader.ReadCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, checkpoint)
	assert.NotNil(t, note)
	tileBytes, err := reader.ReadTile(ctx, tileLevel, tileIndex.U(), partialTileSize)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, tileBytes)
	entryBundle, err := reader.ReadEntryBundle(ctx, tileIndex.U(), partialTileSize)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, entryBundle)
}

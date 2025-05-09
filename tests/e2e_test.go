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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"

	pbdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	dsset "github.com/sigstore/rekor-tiles/pkg/types/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor-tiles/pkg/client/read"
	"github.com/sigstore/rekor-tiles/pkg/client/write"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/trillian-tessera/api"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/sync/errgroup"
)

const (
	defaultRekorURL        = "http://localhost:3003"
	defaultRekorHostname   = "rekor-local"
	defaultGCSURL          = "http://localhost:7080/tiles"
	defaultServerPublicKey = "./testdata/pki/ed25519-pub-key.pem"
)

func TestReadWrite(t *testing.T) {
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
	reader, err := read.NewReader(defaultGCSURL, defaultRekorHostname, verifier)
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
	hrEntry := e.Spec.GetHashedRekordV0_0_2()
	assert.NotNil(t, hrEntry)

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
	dsseEntry := e.Spec.GetDsseV0_0_2()
	assert.NotNil(t, dsseEntry)

	// Add a second identical entries immediately to check for deduplication
	// TODO(#158): add more advanced deduplication checking when the Spanner emulator supports the "batch write" operation
	// (https://cloud.google.com/spanner/docs/batch-write) (https://github.com/GoogleCloudPlatform/cloud-spanner-emulator/issues/172).
	oldIndex := tle.LogIndex
	_, err = writer.Add(ctx, dr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected response: 409")
	assert.ErrorContains(t, err, fmt.Sprintf("an equivalent entry already exists in the transparency log with index %d", oldIndex))
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
	assert.ErrorContains(t, err, "405") // the reader client drops the request body, hence why we only check the status code
	_, err = reader.ReadTile(ctx, 0, 0, 0)
	assert.ErrorContains(t, err, "405")
	_, err = reader.ReadEntryBundle(ctx, 0, 0)
	assert.ErrorContains(t, err, "405")
}

func artifactDigest(idx uint64) []byte {
	baseArtifact := "testartifact"
	artifact := []byte(fmt.Sprintf("%s%d", baseArtifact, idx))
	digest := sha256.Sum256(artifact)
	return digest[:]
}

func genKeys() (*ecdsa.PrivateKey, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func newHashedRekordRequest(privKey *ecdsa.PrivateKey, pubKey []byte, idx uint64) (*pb.HashedRekordRequestV0_0_2, error) {
	digest := artifactDigest(idx)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}
	return &pb.HashedRekordRequestV0_0_2{
		Signature: &pb.Signature{
			Content: sig,
			Verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{
						RawBytes: pubKey,
					},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
		Digest: digest,
	}, nil
}

func newDSSEEnvelope(privKey *ecdsa.PrivateKey) (*pbdsse.Envelope, error) {
	ecdsaSigner, err := signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	envelopeSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: ecdsaSigner,
	})
	if err != nil {
		return nil, err
	}
	payload := "payload"
	payloadType := "application/vnd.in-toto+json"
	envelope, err := envelopeSigner.SignPayload(context.Background(), payloadType, []byte(payload))
	if err != nil {
		return nil, err
	}
	return dsset.ToProto(envelope)
}

func newDSSERequest(privKey *ecdsa.PrivateKey, pubKey []byte) (*pb.DSSERequestV0_0_2, error) {
	envelope, err := newDSSEEnvelope(privKey)
	if err != nil {
		return nil, err
	}
	return &pb.DSSERequestV0_0_2{
		Envelope: envelope,
		Verifiers: []*pb.Verifier{
			{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{
						RawBytes: pubKey,
					},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
	}, nil
}

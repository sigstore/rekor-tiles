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
	"crypto/sha256"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

// assertHashedRekordTLE asserts that a HashedRekord TransparencyLogEntry is valid
func assertHashedRekordTLE(t *testing.T, tle *pbs.TransparencyLogEntry, initialTreeSize, numNewEntries uint64, logID []byte, verifier note.Verifier, hr *pb.HashedRekordRequestV002) {
	assert.NotNil(t, tle)

	// Check server does not set deprecated fields
	assert.Zero(t, tle.IntegratedTime)
	assert.Nil(t, tle.InclusionPromise)

	// Check populated fields
	// Assert log index is [initialTreeSize, initialTreeSize+numNewEntries). We can't know the precise index since
	// entry upload is done in parallel.
	assert.GreaterOrEqual(t, tle.LogIndex, int64(initialTreeSize))
	assert.Less(t, tle.LogIndex, int64(initialTreeSize+numNewEntries))
	// Assert log IDs are equivalent
	assert.Equal(t, tle.LogId.KeyId, logID)
	// Assert kind and version match expected values
	assert.Equal(t, tle.KindVersion.Kind, "hashedrekord")
	assert.Equal(t, tle.KindVersion.Version, "0.0.2")
	// Verify checkpoint and inclusion proof
	verifyInclusionProof(t, tle, verifier)
	// Parse canonicalized body and assert entry matches request
	e := &pb.Entry{}
	assert.NotNil(t, tle.CanonicalizedBody)
	err := protojson.Unmarshal(tle.CanonicalizedBody, e)
	assert.NoError(t, err)
	assert.Equal(t, "hashedrekord", e.Kind)
	assert.Equal(t, "0.0.2", e.ApiVersion)
	hrEntry := e.Spec.GetHashedRekordV002()
	assert.NotNil(t, hrEntry)
	assert.Equal(t, hrEntry.Signature, hr.Signature)
	assert.Equal(t, hrEntry.Data.Algorithm, v1.HashAlgorithm_SHA2_256)
	assert.Equal(t, hrEntry.Data.Digest, hr.Digest)
}

// assertDSSETLE asserts that a DSSE TransparencyLogEntry is valid
func assertDSSETLE(t *testing.T, tle *pbs.TransparencyLogEntry, index uint64, logID []byte, verifier note.Verifier, dr *pb.DSSERequestV002) {
	assert.NotNil(t, tle)

	// Check server does not set deprecated fields
	assert.Zero(t, tle.IntegratedTime)
	assert.Nil(t, tle.InclusionPromise)

	// Check populated fields
	// Assert log index. There is a single DSSE upload so the exact index is known
	assert.Equal(t, tle.LogIndex, int64(index))
	// Assert log IDs are equivalent
	assert.Equal(t, tle.LogId.KeyId, logID)
	// Assert kind and version match expected values
	assert.Equal(t, tle.KindVersion.Kind, "dsse")
	assert.Equal(t, tle.KindVersion.Version, "0.0.2")
	// Verify checkpoint and inclusion proof
	verifyInclusionProof(t, tle, verifier)
	// Parse canonicalized body and assert entry matches request
	e := &pb.Entry{}
	assert.NotNil(t, tle.CanonicalizedBody)
	err := protojson.Unmarshal(tle.CanonicalizedBody, e)
	assert.NoError(t, err)
	assert.Equal(t, "dsse", e.Kind)
	assert.Equal(t, "0.0.2", e.ApiVersion)
	dsseEntry := e.Spec.GetDsseV002()
	assert.NotNil(t, dsseEntry)
	// Assert payload hash is as expected
	assert.Equal(t, dsseEntry.PayloadHash.Algorithm, v1.HashAlgorithm_SHA2_256)
	expectedPayloadHash := sha256.Sum256(dr.Envelope.Payload)
	assert.Equal(t, dsseEntry.PayloadHash.Digest, expectedPayloadHash[:])
	// Assert signature matches envelope's signature
	assert.Len(t, dsseEntry.Signatures, 1)
	assert.Equal(t, dsseEntry.Signatures[0].Content, dr.Envelope.Signatures[0].Sig)
	assert.Equal(t, dsseEntry.Signatures[0].Verifier, dr.Verifiers[0])
}

// verifyInclusionProof verifies the inclusion proof in a TransparencyLogEntry
func verifyInclusionProof(t *testing.T, tle *pbs.TransparencyLogEntry, verifier note.Verifier) {
	// Server also verifies inclusion proof before returning response
	assert.NotNil(t, tle.InclusionProof)

	// Verify checkpoint signature
	checkpoint, err := verify.VerifyCheckpoint(tle.InclusionProof.Checkpoint.Envelope, verifier)
	assert.NoError(t, err)

	// Verify duplicated tle.inclusion_proof fields match bundle and parsed checkpoint values
	assert.Equal(t, tle.InclusionProof.LogIndex, tle.LogIndex)
	assert.Equal(t, tle.InclusionProof.TreeSize, int64(checkpoint.Size))
	assert.Equal(t, tle.InclusionProof.RootHash, checkpoint.Hash)

	// Verify inclusion proof
	leafHash := rfc6962.DefaultHasher.HashLeaf(tle.CanonicalizedBody)
	assert.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher,
		uint64(tle.LogIndex),
		checkpoint.Size,
		leafHash,
		tle.InclusionProof.Hashes,
		checkpoint.Hash))
}

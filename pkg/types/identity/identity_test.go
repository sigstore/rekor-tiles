// Copyright 2026 The Sigstore Authors
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

package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/merkle/rfc6962"
)

func generateValidRequest(t *testing.T) (*pb.IdentityRequestV001, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := cryptoutils.MarshalPublicKeyToDER(pub)
	assert.NoError(t, err)

	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)

	k := []byte("key1")
	v := []byte("val1")
	kHash := sha256.Sum256(k)
	vHash := sha256.Sum256(v)

	payload := []byte(SpecDomainSeparatorV1)
	payload = append(payload, 0x00)

	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)

	kDoubleHash := sha256.Sum256(kHash[:])
	vDoubleHash := sha256.Sum256(vHash[:])
	payload = append(payload, kDoubleHash[:]...)
	payload = append(payload, vDoubleHash[:]...)

	sig := ed25519.Sign(priv, payload)

	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
			},
		},
		Message: msgHash[:],
		Context: []*pb.ContextEntry{
			{Key: kHash[:], Value: vHash[:]},
		},
	}
	return req, payload
}

func TestToLogEntry(t *testing.T) {
	req, _ := generateValidRequest(t)

	leafBytes, err := ToLogEntry(req)
	assert.NoError(t, err)
	assert.NotNil(t, leafBytes)
	assert.Greater(t, len(leafBytes), 0)
	assert.Equal(t, byte(0x01), leafBytes[0]) // Leaf hash starts with 0x01
}

func TestToLogEntry_InvalidSignature(t *testing.T) {
	req, _ := generateValidRequest(t)

	// Invalidate the signature by flipping the first byte
	req.GetPublicKey().Signature[0] ^= 0xFF

	leafBytes, err := ToLogEntry(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
	assert.Nil(t, leafBytes)
}

func TestValidate_InvalidMessageSize(t *testing.T) {
	req, _ := generateValidRequest(t)

	// Invalid message size
	req.Message = []byte("short")

	err := validate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message hash size")
}

func TestSortContext(t *testing.T) {
	req, _ := generateValidRequest(t)

	k1 := bytes.Repeat([]byte{0x02}, 32)
	k2 := bytes.Repeat([]byte{0x01}, 32)

	req.Context = []*pb.ContextEntry{
		{Key: k1, Value: k1},
		{Key: k2, Value: k2},
	}

	sorted := sortContext(req.Context)

	// Verify that Context has been sorted
	assert.Equal(t, k2, sorted[0].Key)
	assert.Equal(t, k1, sorted[1].Key)
}

func TestToEntryHash(t *testing.T) {
	req, _ := generateValidRequest(t)

	leafBytes, err := ToLogEntry(req)
	assert.NoError(t, err)

	expectedHash := rfc6962.DefaultHasher.HashLeaf(leafBytes)

	ctxMap := make(map[string]string)
	for _, c := range req.Context {
		ctxMap[hex.EncodeToString(c.Key)] = hex.EncodeToString(c.Value)
	}

	h, err := ToEntryHash(req.GetPublicKey().GetPublicKey(), req.GetPublicKey().GetSignature(), req.Message, ctxMap)
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, h)
}

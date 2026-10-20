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

package identity_v1

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/merkle/rfc6962"
)

func generateValidRequest(t *testing.T) (*pb.IdentityRequestV001, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	assert.NoError(t, err)

	msg := []byte("test message")
	msgHash := sha256.Sum256(msg)

	v := []byte("val1")
	vHash := sha256.Sum256(v)

	payload := []byte(SpecDomainSeparator)
	payload = append(payload, 0x00)

	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)

	k1 := sha256.Sum256([]byte(ContextKeyName))
	kDoubleHash := sha256.Sum256(k1[:])
	vDoubleHash := sha256.Sum256(vHash[:])
	payload = append(payload, kDoubleHash[:]...)
	payload = append(payload, vDoubleHash[:]...)

	sig := ed25519.Sign(priv, payload)

	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
				Context:   vHash[:],
			},
		},
		Message: msgHash[:],
	}
	return req, payload
}

func TestToLogEntry(t *testing.T) {
	req, _ := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, err := ToLogEntry(req, algReg)
	assert.NoError(t, err)
	assert.NotNil(t, leafBytes)
	assert.Len(t, leafBytes, 1+4*sha256.Size+sha256.Size)
	assert.Equal(t, LeafVersion, leafBytes[0])

	rootOfTrust := append([]byte("Ed25519"), req.GetPublicKey().GetPublicKey()...)
	rootPubKeyHash := sha256.Sum256(rootOfTrust)
	assert.Equal(t, rootPubKeyHash[:], leafBytes[1:33]) // H(RoT) comes first after version byte

	msgHash := sha256.Sum256(req.GetMessage())
	assert.Equal(t, msgHash[:], leafBytes[33:65]) // H(H(data)) comes second after version byte

	k1 := sha256.Sum256([]byte(ContextKeyName))
	kDoubleHash := sha256.Sum256(k1[:])
	assert.Equal(t, kDoubleHash[:], leafBytes[65:97]) // H(H("context"))

	vDoubleHash := sha256.Sum256(req.GetPublicKey().GetContext())
	assert.Equal(t, vDoubleHash[:], leafBytes[97:129]) // H(H(contextVal))

	sigHash := sha256.Sum256(req.GetPublicKey().GetSignature())
	assert.Equal(t, sigHash[:], leafBytes[129:161]) // H(signature)
}

func TestToLogEntry_NoContext(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	assert.NoError(t, err)

	msgHash := sha256.Sum256([]byte("test message"))
	payload := append([]byte(SpecDomainSeparator), 0x00)
	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)
	sig := ed25519.Sign(priv, payload)

	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
			},
		},
		Message: msgHash[:],
	}

	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, err := ToLogEntry(req, algReg)
	assert.NoError(t, err)
	assert.Len(t, leafBytes, 1+3*sha256.Size)
	assert.Equal(t, LeafVersion, leafBytes[0])

	sigHash := sha256.Sum256(sig)
	assert.Equal(t, sigHash[:], leafBytes[65:97])
}

func TestToLogEntry_InvalidSignature(t *testing.T) {
	req, _ := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	// Invalidate the signature by flipping the first byte
	req.GetPublicKey().Signature[0] ^= 0xFF

	leafBytes, err := ToLogEntry(req, algReg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_InvalidSignatureLength(t *testing.T) {
	req, _ := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	req.GetPublicKey().Signature = []byte("short-sig")

	leafBytes, err := ToLogEntry(req, algReg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature length, must be 64 bytes for Ed25519")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_UnsupportedAlgorithm(t *testing.T) {
	req, _ := generateValidRequest(t)
	// Client algorithm registry does not permit pure Ed25519
	algReg, err := algorithmregistry.AlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, err := ToLogEntry(req, algReg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported entry algorithm for Ed25519 key, digest none")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_InvalidPublicKey(t *testing.T) {
	req, _ := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	req.GetPublicKey().PublicKey = []byte("not-valid-der")

	leafBytes, err := ToLogEntry(req, algReg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public key")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_NonEd25519Key(t *testing.T) {
	req, _ := generateValidRequest(t)
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	ecdsaDER, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	assert.NoError(t, err)
	req.GetPublicKey().PublicKey = ecdsaDER

	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, err := ToLogEntry(req, algReg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported entry algorithm for ECDSA key, curve P-256, digest none")
	assert.Nil(t, leafBytes)

	leafBytes, err = ToLogEntry(req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key is not an Ed25519 key")
	assert.Nil(t, leafBytes)
}

func TestValidate(t *testing.T) {
	validReq, _ := generateValidRequest(t)

	tests := []struct {
		name        string
		mutate      func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001
		errContains string
	}{
		{
			name:        "nil request",
			mutate:      func(_ *pb.IdentityRequestV001) *pb.IdentityRequestV001 { return nil },
			errContains: "request is nil",
		},
		{
			name: "missing credential",
			mutate: func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001 {
				r.Credential = nil
				return r
			},
			errContains: "unsupported or missing credential type",
		},
		{
			name: "empty public key",
			mutate: func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001 {
				r.GetPublicKey().PublicKey = nil
				return r
			},
			errContains: "public key is empty",
		},
		{
			name: "empty signature",
			mutate: func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001 {
				r.GetPublicKey().Signature = nil
				return r
			},
			errContains: "signature is empty",
		},
		{
			name: "invalid context size",
			mutate: func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001 {
				r.GetPublicKey().Context = []byte("short")
				return r
			},
			errContains: "invalid context value hash size",
		},
		{
			name: "invalid message size",
			mutate: func(r *pb.IdentityRequestV001) *pb.IdentityRequestV001 {
				r.Message = []byte("short")
				return r
			},
			errContains: "invalid message hash size",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqCopy := &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: validReq.GetPublicKey().GetPublicKey(),
						Signature: validReq.GetPublicKey().GetSignature(),
						Context:   validReq.GetPublicKey().GetContext(),
					},
				},
				Message: validReq.GetMessage(),
			}
			err := validate(tc.mutate(reqCopy))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestToEntryHash(t *testing.T) {
	req, _ := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, err := ToLogEntry(req, algReg)
	assert.NoError(t, err)

	expectedHash := rfc6962.DefaultHasher.HashLeaf(leafBytes)

	h, err := ToEntryHash(req.GetPublicKey().GetPublicKey(), req.GetPublicKey().GetSignature(), req.Message, req.GetPublicKey().GetContext())
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, h)
}

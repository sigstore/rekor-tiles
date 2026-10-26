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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"testing"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/server"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/merkle/rfc6962"
)

func generateTestPayload() (msgHash [sha256.Size]byte, contextHash [sha256.Size]byte, payload []byte) {
	msgHash = sha256.Sum256([]byte("test message"))
	contextHash = sha256.Sum256([]byte("val1"))

	payload = []byte(SpecDomainSeparator)
	payload = append(payload, 0x00)

	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)

	k1 := sha256.Sum256([]byte(ContextKeyName))
	kDoubleHash := sha256.Sum256(k1[:])
	vDoubleHash := sha256.Sum256(contextHash[:])
	payload = append(payload, kDoubleHash[:]...)
	payload = append(payload, vDoubleHash[:]...)
	return msgHash, contextHash, payload
}

func generateValidRequest(t *testing.T) *pb.IdentityRequestV001 {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	assert.NoError(t, err)

	msgHash, vHash, payload := generateTestPayload()
	sig := ed25519.Sign(priv, payload)

	return &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
				Context:   vHash[:],
			},
		},
		Message: msgHash[:],
	}
}

func generateValidMLDSARequest(t *testing.T) *pb.IdentityRequestV001 {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	assert.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	assert.NoError(t, err)

	msgHash, vHash, payload := generateTestPayload()
	sig, err := priv.Sign(nil, payload, nil)
	assert.NoError(t, err)

	return &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
				Context:   vHash[:],
			},
		},
		Message: msgHash[:],
	}
}

func TestToLogEntry(t *testing.T) {
	req := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, extraData, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, leafBytes)
	assert.Len(t, leafBytes, 1+4*sha256.Size+sha256.Size)
	assert.Equal(t, LeafVersion, leafBytes[0])
	assert.Equal(t, fmt.Appendf(nil, "%s:%s", ContextKeyName, base64.StdEncoding.EncodeToString(req.GetPublicKey().GetContext())), extraData)

	rootOfTrust := append([]byte("Ed25519"), req.GetPublicKey().GetPublicKey()...)
	rootOfTrustHash := sha256.Sum256(rootOfTrust)
	assert.Equal(t, rootOfTrustHash[:], leafBytes[1:33]) // H(RoT) comes first after version byte

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

	leafBytes, extraData, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.NoError(t, err)
	assert.Nil(t, extraData)
	assert.Len(t, leafBytes, 1+3*sha256.Size)
	assert.Equal(t, LeafVersion, leafBytes[0])

	sigHash := sha256.Sum256(sig)
	assert.Equal(t, sigHash[:], leafBytes[65:97])
}

func TestToLogEntry_InvalidSignature(t *testing.T) {
	req := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	// Invalidate the signature by flipping the first byte
	req.GetPublicKey().Signature[0] ^= 0xFF

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_MLDSA(t *testing.T) {
	req := generateValidMLDSARequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, extraData, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, leafBytes)
	assert.Len(t, leafBytes, 1+4*sha256.Size+sha256.Size)
	assert.Equal(t, LeafVersion, leafBytes[0])
	assert.Equal(t, fmt.Appendf(nil, "%s:%s", ContextKeyName, base64.StdEncoding.EncodeToString(req.GetPublicKey().GetContext())), extraData)

	rootOfTrust := append([]byte("ML-DSA-44"), req.GetPublicKey().GetPublicKey()...)
	rootOfTrustHash := sha256.Sum256(rootOfTrust)
	assert.Equal(t, rootOfTrustHash[:], leafBytes[1:33])

	msgHash := sha256.Sum256(req.GetMessage())
	assert.Equal(t, msgHash[:], leafBytes[33:65])

	k1 := sha256.Sum256([]byte(ContextKeyName))
	kDoubleHash := sha256.Sum256(k1[:])
	assert.Equal(t, kDoubleHash[:], leafBytes[65:97])

	vDoubleHash := sha256.Sum256(req.GetPublicKey().GetContext())
	assert.Equal(t, vDoubleHash[:], leafBytes[97:129])

	sigHash := sha256.Sum256(req.GetPublicKey().GetSignature())
	assert.Equal(t, sigHash[:], leafBytes[129:161])
}

func TestToLogEntry_InvalidSignature_MLDSA(t *testing.T) {
	req := generateValidMLDSARequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	// Invalidate the signature by flipping the first byte
	req.GetPublicKey().Signature[0] ^= 0xFF

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_InvalidSignatureLength(t *testing.T) {
	req := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	req.GetPublicKey().Signature = []byte("short-sig")

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature length, must be 64 bytes for Ed25519")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_InvalidSignatureLength_MLDSA(t *testing.T) {
	req := generateValidMLDSARequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	req.GetPublicKey().Signature = []byte("short-sig")

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature length, must be 2420 bytes for ML-DSA-44")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_UnsupportedAlgorithm(t *testing.T) {
	req := generateValidRequest(t)
	// Client algorithm registry does not permit pure Ed25519
	algReg, err := algorithmregistry.AlgorithmRegistry(nil)
	assert.NoError(t, err)

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported entry algorithm for Ed25519 key, digest none")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_InvalidPublicKey(t *testing.T) {
	req := generateValidRequest(t)
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	req.GetPublicKey().PublicKey = []byte("not-valid-der")

	leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public key")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_UnsupportedPublicKey(t *testing.T) {
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	t.Run("ECDSA", func(t *testing.T) {
		req := generateValidRequest(t)
		ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NoError(t, err)
		ecdsaDER, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
		assert.NoError(t, err)
		req.GetPublicKey().PublicKey = ecdsaDER

		leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported entry algorithm for ECDSA key, curve P-256, digest none")
		assert.Nil(t, leafBytes)

		leafBytes, _, err = ToLogEntry(context.Background(), req, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported public key type")
		assert.Nil(t, leafBytes)
	})

	t.Run("ML-DSA-65", func(t *testing.T) {
		req := generateValidRequest(t)
		mldsa65Priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
		assert.NoError(t, err)
		mldsa65DER, err := x509.MarshalPKIXPublicKey(mldsa65Priv.PublicKey())
		assert.NoError(t, err)
		req.GetPublicKey().PublicKey = mldsa65DER

		leafBytes, _, err := ToLogEntry(context.Background(), req, algReg, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported entry algorithm for ML-DSA key, parameter set ML-DSA-65, digest none")
		assert.Nil(t, leafBytes)

		leafBytes, _, err = ToLogEntry(context.Background(), req, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key is not an ML-DSA-44 key")
		assert.Nil(t, leafBytes)
	})
}

func TestValidate(t *testing.T) {
	validReq := generateValidRequest(t)

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
	algReg, err := algorithmregistry.IdentityAlgorithmRegistry(nil)
	assert.NoError(t, err)

	tests := []struct {
		name string
		req  *pb.IdentityRequestV001
	}{
		{
			name: "Ed25519",
			req:  generateValidRequest(t),
		},
		{
			name: "ML-DSA-44",
			req:  generateValidMLDSARequest(t),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafBytes, _, err := ToLogEntry(context.Background(), tc.req, algReg, nil)
			assert.NoError(t, err)

			expectedHash := rfc6962.DefaultHasher.HashLeaf(leafBytes)

			h, err := ToEntryHash(tc.req.GetPublicKey().GetPublicKey(), tc.req.GetPublicKey().GetSignature(), tc.req.Message, tc.req.GetPublicKey().GetContext())
			assert.NoError(t, err)
			assert.Equal(t, expectedHash, h)
		})
	}
}

func TestValidate_OidcEmptyToken(t *testing.T) {
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_Oidc{
			Oidc: &pb.OidcCredential{
				Token: "",
			},
		},
		Message: bytes.Repeat([]byte{0x00}, 32),
	}

	err := validate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oidc token is empty")
}

func TestToLogEntry_OidcInvalidToken(t *testing.T) {
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_Oidc{
			Oidc: &pb.OidcCredential{
				Token: "invalid.token.here",
			},
		},
		Message: bytes.Repeat([]byte{0x00}, 32),
	}

	leafBytes, _, err := ToLogEntry(context.Background(), req, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oidc config must be provided")
	assert.Nil(t, leafBytes)

	cfg, err := config.Read([]byte("{}"))
	assert.NoError(t, err)
	ctx := config.With(context.Background(), cfg)
	pool := server.NewIssuerPool(cfg)

	leafBytes, _, err = ToLogEntry(ctx, req, nil, pool)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate token")
	assert.Nil(t, leafBytes)
}

func TestToLogEntry_OidcValid(t *testing.T) {
	ctx := context.Background()
	m := newMockOIDC(t)
	defer m.server.Close()

	cfgJSON := fmt.Sprintf(`{
		"OIDCIssuers": {
			"%s": {
				"IssuerURL": "%s",
				"ClientID":  "sigstore",
				"Type":      "email"
			}
		}
	}`, m.server.URL, m.server.URL)
	cfg, err := config.Read([]byte(cfgJSON))
	assert.NoError(t, err)
	ctx = config.With(ctx, cfg)
	pool := server.NewIssuerPool(cfg)

	tok := m.token(t, "test-sub", "foo@example.com")
	msgHash := sha256.Sum256([]byte("test message"))
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_Oidc{
			Oidc: &pb.OidcCredential{
				Token: tok,
			},
		},
		Message: msgHash[:],
	}

	leafBytes, extraData, err := ToLogEntry(ctx, req, nil, pool)
	assert.NoError(t, err)
	expectedClaims := map[string]string{
		"identity": "foo@example.com",
		"issuer":   m.server.URL,
		"subject":  "test-sub",
	}
	assert.Equal(t, fmt.Appendf(nil, "identity:%s\nissuer:%s\nsubject:%s",
		base64.StdEncoding.EncodeToString([]byte("foo@example.com")),
		base64.StdEncoding.EncodeToString([]byte(m.server.URL)),
		base64.StdEncoding.EncodeToString([]byte("test-sub"))), extraData)

	// Expected leaf layout:
	// 1 byte version (0x01) + 32B SHA256(issuer) + 32B SHA256(msgHash) +
	// 3 * 64B sorted (SHA256(SHA256(k)) || SHA256(SHA256(v))) + 32B zero receipt
	expectedLen := 1 + 32 + 32 + len(expectedClaims)*64 + 32
	assert.Len(t, leafBytes, expectedLen)
	assert.Equal(t, LeafVersion, leafBytes[0])

	expectedRootHash := sha256.Sum256([]byte(m.server.URL))
	assert.Equal(t, expectedRootHash[:], leafBytes[1:33])

	expectedMsgDoubleHash := sha256.Sum256(msgHash[:])
	assert.Equal(t, expectedMsgDoubleHash[:], leafBytes[33:65])

	type kvHash struct {
		k [32]byte
		v [32]byte
	}
	var expectedPairs []kvHash
	for k, v := range expectedClaims {
		kh := sha256.Sum256([]byte(k))
		vh := sha256.Sum256([]byte(v))
		expectedPairs = append(expectedPairs, kvHash{
			k: sha256.Sum256(kh[:]),
			v: sha256.Sum256(vh[:]),
		})
	}
	slices.SortFunc(expectedPairs, func(a, b kvHash) int {
		return bytes.Compare(a.k[:], b.k[:])
	})
	offset := 65
	for _, p := range expectedPairs {
		assert.Equal(t, p.k[:], leafBytes[offset:offset+32])
		assert.Equal(t, p.v[:], leafBytes[offset+32:offset+64])
		offset += 64
	}
	assert.Equal(t, make([]byte, 32), leafBytes[offset:offset+32])
}

func TestToOIDCEntryHash(t *testing.T) {
	ctx := context.Background()
	m := newMockOIDC(t)
	defer m.server.Close()

	cfgJSON := fmt.Sprintf(`{
		"OIDCIssuers": {
			"%s": {
				"IssuerURL": "%s",
				"ClientID":  "sigstore",
				"Type":      "email"
			}
		}
	}`, m.server.URL, m.server.URL)
	cfg, err := config.Read([]byte(cfgJSON))
	assert.NoError(t, err)
	ctx = config.With(ctx, cfg)
	pool := server.NewIssuerPool(cfg)

	tok := m.token(t, "test-sub", "foo@example.com")
	msgHash := sha256.Sum256([]byte("test message"))
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_Oidc{
			Oidc: &pb.OidcCredential{
				Token: tok,
			},
		},
		Message: msgHash[:],
	}

	leafBytes, _, err := ToLogEntry(ctx, req, nil, pool)
	assert.NoError(t, err)
	expectedHash := rfc6962.DefaultHasher.HashLeaf(leafBytes)

	claims := map[string]string{
		"identity": "foo@example.com",
		"issuer":   m.server.URL,
		"subject":  "test-sub",
	}
	gotHash, err := ToOIDCEntryHash(msgHash[:], claims)
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, gotHash)

	_, err = ToOIDCEntryHash([]byte("short"), claims)
	assert.ErrorContains(t, err, "invalid message hash size")

	delete(claims, "issuer")
	_, err = ToOIDCEntryHash(msgHash[:], claims)
	assert.ErrorContains(t, err, "issuer claim is missing or empty")
}

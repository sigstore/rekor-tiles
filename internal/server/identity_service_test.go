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

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sigstore/fulcio/pkg/config"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/identity_v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/formats/proof"
	ttessera "github.com/transparency-dev/tessera"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupMockOIDC(t *testing.T) (*config.FulcioConfig, string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	require.NoError(t, err)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	claims := struct {
		jwt.Claims
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}{
		Issuer:        srv.URL,
		Subject:       "test-sub",
		Audience:      jwt.Audience{"sigstore"},
		Expiry:        jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:      jwt.NewNumericDate(time.Now()),
		Email:         "foo@example.com",
		EmailVerified: true,
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	cfgJSON := fmt.Sprintf(`{
		"OIDCIssuers": {
			"%s": {
				"IssuerURL": "%s",
				"ClientID":  "sigstore",
				"Type":      "email"
			}
		}
	}`, srv.URL, srv.URL)
	cfg, err := config.Read([]byte(cfgJSON))
	require.NoError(t, err)

	return cfg, tok, srv.URL
}

func TestCreateIdentityEntry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	msgHash := sha256.Sum256([]byte("hello world"))
	payload := []byte("c2sp.org/identity-transparency/v1\x00")
	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)
	sig := ed25519.Sign(priv, payload)

	contextVal := sha256.Sum256([]byte("bar"))
	contextPayload := append([]byte{}, payload...)
	k1 := sha256.Sum256([]byte(identity_v1.ContextKeyName))
	kDoubleHash := sha256.Sum256(k1[:])
	vDoubleHash := sha256.Sum256(contextVal[:])
	contextPayload = append(contextPayload, kDoubleHash[:]...)
	contextPayload = append(contextPayload, vDoubleHash[:]...)
	contextSig := ed25519.Sign(priv, contextPayload)

	defaultAlgReg, err := algorithmregistry.IdentityAlgorithmRegistry([]string{"ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	disallowedAlgReg, err := algorithmregistry.AlgorithmRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}

	oidcCfg, oidcTok, oidcIssuerURL := setupMockOIDC(t)

	validReq := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
			},
		},
		Message: msgHash[:],
	}

	proofHash := bytes.Repeat([]byte{0xab}, sha256.Size)

	tests := []struct {
		name              string
		req               *pb.IdentityRequestV001
		readOnly          bool
		algReg            *signature.AlgorithmRegistryConfig
		addFn             func() (*rekor_pb.TransparencyLogEntry, error)
		expectError       error
		expectedCode      codes.Code
		expectedExtraData []byte
	}{
		{
			name: "valid request",
			req:  validReq,
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{
					InclusionProof: &rekor_pb.InclusionProof{
						LogIndex:   1,
						Hashes:     [][]byte{proofHash},
						Checkpoint: &rekor_pb.Checkpoint{Envelope: "checkpoint"},
					},
				}, nil
			},
		},
		{
			name: "valid request with context",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: contextSig,
						Context:   contextVal[:],
					},
				},
				Message: msgHash[:],
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{
					InclusionProof: &rekor_pb.InclusionProof{
						LogIndex:   1,
						Hashes:     [][]byte{proofHash},
						Checkpoint: &rekor_pb.Checkpoint{Envelope: "checkpoint"},
					},
				}, nil
			},
			expectedExtraData: fmt.Appendf(nil, "%s:%s", identity_v1.ContextKeyName, hex.EncodeToString(contextVal[:])),
		},
		{
			name: "valid oidc request",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_Oidc{
					Oidc: &pb.OidcCredential{
						Token: oidcTok,
					},
				},
				Message: msgHash[:],
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{
					InclusionProof: &rekor_pb.InclusionProof{
						LogIndex:   1,
						Hashes:     [][]byte{proofHash},
						Checkpoint: &rekor_pb.Checkpoint{Envelope: "checkpoint"},
					},
				}, nil
			},
			expectedExtraData: fmt.Appendf(nil, "identity:foo@example.com\nissuer:%s\nsubject:test-sub", oidcIssuerURL),
		},
		{
			name:         "read-only mode",
			req:          validReq,
			readOnly:     true,
			addFn:        func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			expectError:  fmt.Errorf("log frozen"),
			expectedCode: codes.Unimplemented,
		},
		{
			name: "failed validation",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: sig,
					},
				},
				Message: make([]byte, 31), // invalid message length
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{}, nil
			},
			expectError:  fmt.Errorf("invalid identity request"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "disallowed algorithm",
			req:          validReq,
			algReg:       disallowedAlgReg,
			addFn:        func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			expectError:  fmt.Errorf("invalid identity request"),
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "pushback",
			req:          validReq,
			addFn:        func() (*rekor_pb.TransparencyLogEntry, error) { return nil, ttessera.ErrPushback },
			expectError:  fmt.Errorf("reached max pushback; retry"),
			expectedCode: codes.Unavailable,
		},
		{
			name:         "context canceled",
			req:          validReq,
			addFn:        func() (*rekor_pb.TransparencyLogEntry, error) { return nil, context.Canceled },
			expectError:  fmt.Errorf("context canceled"),
			expectedCode: codes.Canceled,
		},
		{
			name:         "duplicate entry",
			req:          validReq,
			addFn:        func() (*rekor_pb.TransparencyLogEntry, error) { return nil, tessera.DuplicateError{} },
			expectError:  fmt.Errorf("an equivalent entry already exists in the transparency log"),
			expectedCode: codes.AlreadyExists,
		},
		{
			name: "failed integration",
			req:  validReq,
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return nil, fmt.Errorf("timed out")
			},
			expectError:  fmt.Errorf("failed to integrate entry"),
			expectedCode: codes.Unknown,
		},
		{
			name: "inclusion proof verification failure",
			req:  validReq,
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return nil, tessera.InclusionProofVerificationError{}
			},
			expectError:  fmt.Errorf("failed to integrate entry"),
			expectedCode: codes.Unknown,
		},
		{
			name: "index out of bounds",
			req:  validReq,
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{
					InclusionProof: &rekor_pb.InclusionProof{
						LogIndex:   -1,
						Checkpoint: &rekor_pb.Checkpoint{Envelope: "checkpoint"},
					},
				}, nil
			},
			expectError:  fmt.Errorf("internal error, index out of bounds"),
			expectedCode: codes.Internal,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockStorage{addFn: test.addFn}
			algReg := test.algReg
			if algReg == nil {
				algReg = defaultAlgReg
			}
			server := NewIdentityServer(storage, test.readOnly, algReg, oidcCfg)

			gotBody, gotErr := server.CreateEntry(context.Background(), test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotBody)
				assert.Equal(t, "text/plain", gotBody.ContentType)

				var p proof.TLogProof
				assert.NoError(t, p.Unmarshal(gotBody.Data))
				assert.Equal(t, uint64(1), p.Index)
				assert.Len(t, p.Hashes, 1)
				assert.Equal(t, proofHash, p.Hashes[0][:])
				assert.Equal(t, []byte("checkpoint\n"), p.Checkpoint)
				assert.Equal(t, test.expectedExtraData, p.ExtraData)
			} else {
				s, ok := status.FromError(gotErr)
				assert.True(t, ok)
				assert.Equal(t, test.expectedCode, s.Code())
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

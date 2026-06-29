// Copyright 2025 The Sigstore Authors
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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateIdentityEntry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToDER(pub)
	if err != nil {
		t.Fatal(err)
	}

	msgHash := sha256.Sum256([]byte("hello world"))
	payload := []byte("c2sp.org/identity-transparency/v1\x00")
	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)
	sig := ed25519.Sign(priv, payload)

	tests := []struct {
		name         string
		req          *pb.IdentityRequestV001
		addFn        func() (*rekor_pb.TransparencyLogEntry, error)
		expectError  error
		expectedCode codes.Code
	}{
		{
			name: "valid request",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: sig,
						Algorithm: v1.PublicKeyDetails_PKIX_ED25519,
					},
				},
				Message: msgHash[:],
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return &rekor_pb.TransparencyLogEntry{
					InclusionProof: &rekor_pb.InclusionProof{
						LogIndex:   1,
						Checkpoint: &rekor_pb.Checkpoint{Envelope: "checkpoint"},
					},
				}, nil
			},
		},
		{
			name: "failed validation",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: sig,
						Algorithm: v1.PublicKeyDetails_PKIX_ED25519,
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
			name: "failed integration",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: sig,
						Algorithm: v1.PublicKeyDetails_PKIX_ED25519,
					},
				},
				Message: msgHash[:],
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return nil, fmt.Errorf("timed out")
			},
			expectError:  fmt.Errorf("failed to integrate entry"),
			expectedCode: codes.Unknown,
		},
		{
			name: "inclusion proof verification failure",
			req: &pb.IdentityRequestV001{
				Credential: &pb.IdentityRequestV001_PublicKey{
					PublicKey: &pb.PublicKeyCredential{
						PublicKey: pubBytes,
						Signature: sig,
						Algorithm: v1.PublicKeyDetails_PKIX_ED25519,
					},
				},
				Message: msgHash[:],
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) {
				return nil, tessera.InclusionProofVerificationError{}
			},
			expectError:  fmt.Errorf("failed to integrate entry"),
			expectedCode: codes.Unknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockStorage{addFn: test.addFn}
			algReg, err := algorithmregistry.AlgorithmRegistry([]string{"ed25519"})
			if err != nil {
				t.Fatal(err)
			}
			server := NewIdentityServer(storage, false, algReg, []byte{1}, nil)

			gotBody, gotErr := server.CreateEntry(context.Background(), test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotBody)
				assert.Equal(t, "text/plain", gotBody.ContentType)
			} else {
				s, ok := status.FromError(gotErr)
				assert.True(t, ok)
				assert.Equal(t, test.expectedCode, s.Code())
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

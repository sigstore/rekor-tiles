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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	ttessera "github.com/transparency-dev/tessera"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewServer(t *testing.T) {
	storage := &mockStorage{}
	algReg, err := algorithmregistry.AlgorithmRegistry([]string{"ecdsa-sha2-256-nistp256"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(storage, false, algReg, []byte{1})
	assert.NoError(t, err)
	assert.NotNil(t, server.storage)
	assert.NotNil(t, server.algorithmRegistry)
}

func TestCreateEntry(t *testing.T) {
	tests := []struct {
		name                    string
		req                     *pb.CreateEntryRequest
		addFn                   func() (*rekor_pb.TransparencyLogEntry, error)
		clientSigningAlgorithms []string
		expectError             error
		expectedCode            codes.Code
	}{
		{
			name: "valid hashedrekord",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
		},
		{
			name: "valid dsse",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_DsseRequestV002{
					DsseRequestV002: &pb.DSSERequestV002{
						Envelope: &dsse.Envelope{
							Payload:     b64DecodeOrDie(t, "cGF5bG9hZA=="),
							PayloadType: "application/vnd.in-toto+json",
							Signatures: []*dsse.Signature{
								{
									Sig:   b64DecodeOrDie(t, "MEUCIQCSWas1Y9bI7aDNrBdHlzrFH8ch7B7IM+pJK86mtjkbJAIgaeCltz6vs20DP2sJ7IBihvcrdqGn3ivuV/KNPlMOetk="),
									Keyid: "",
								},
							},
						},
						Verifiers: []*pb.Verifier{
							{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE850nB+WrwXzivt7yFbhFKw/8M2paqSTHiQhkA4/0ZAsJtmzn/v4HdeZKTCQcsHq5IwM/LtbmEdv9ChO9M3cg9g=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
		},
		{
			name: "invalid hashedrekord",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("invalid hashedrekord request"),
			expectedCode:            codes.InvalidArgument,
		},
		{
			name: "invalid dsse",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_DsseRequestV002{
					DsseRequestV002: &pb.DSSERequestV002{},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("invalid dsse request"),
			expectedCode:            codes.InvalidArgument,
		},
		{
			name: "context canceled",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return nil, context.Canceled },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("context canceled"),
			expectedCode:            codes.Canceled,
		},
		{
			name: "duplicate entry",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return nil, tessera.DuplicateError{} },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("an equivalent entry already exists in the transparency log"),
			expectedCode:            codes.AlreadyExists,
		},
		{
			name: "inclusion proof verification failure",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return nil, tessera.InclusionProofVerificationError{} },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("failed to integrate entry"),
			expectedCode:            codes.Unknown,
		},
		{
			name: "failed integration",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: b64DecodeOrDie(t, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ=="),
									},
								},
								KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return nil, fmt.Errorf("timed out") },
			clientSigningAlgorithms: []string{"ecdsa-sha2-256-nistp256"},
			expectError:             fmt.Errorf("failed to integrate entry"),
			expectedCode:            codes.Unknown,
		},
		{
			name: "hashedrekord signed with disallowed algorithm",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV002{
					HashedRekordRequestV002: &pb.HashedRekordRequestV002{
						Signature: &pb.Signature{
							Content: b64DecodeOrDie(t, "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"),
							Verifier: &pb.Verifier{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p
2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END PUBLIC KEY-----`),
									},
								},
							},
						},
						Digest: hexDecodeOrDie(t, "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"),
					},
				},
			},
			addFn:                   func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			clientSigningAlgorithms: []string{"rsa-sign-pkcs1-4096-sha256"},
			expectError:             fmt.Errorf("invalid hashedrekord request"),
			expectedCode:            codes.InvalidArgument,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockStorage{addFn: test.addFn}
			algReg, err := algorithmregistry.AlgorithmRegistry(test.clientSigningAlgorithms)
			if err != nil {
				t.Fatal(err)
			}
			server := NewServer(storage, false, algReg, []byte{1})
			gotTle, gotErr := server.CreateEntry(context.Background(), test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotTle)
				// Check that the fields set by the service are populated
				assert.NotNil(t, gotTle.KindVersion)
				assert.NotNil(t, gotTle.LogId)
			} else {
				s, ok := status.FromError(gotErr)
				assert.True(t, ok)
				assert.Equal(t, s.Code(), test.expectedCode)
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

type mockStorage struct {
	addFn func() (*rekor_pb.TransparencyLogEntry, error)
}

func (s *mockStorage) Add(_ context.Context, _ *ttessera.Entry) (*rekor_pb.TransparencyLogEntry, error) {
	return s.addFn()
}

func (s *mockStorage) ReadTile(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
	return nil, nil
}

func hexDecodeOrDie(t *testing.T, hash string) []byte {
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func b64DecodeOrDie(t *testing.T, msg string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

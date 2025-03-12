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
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	ttessera "github.com/transparency-dev/trillian-tessera"
)

func TestNewServer(t *testing.T) {
	storage := &mockStorage{}
	server := NewServer(storage)
	expectServer := &Server{storage: &mockStorage{}}
	assert.Equal(t, expectServer, server)
}

func TestCreateEntry(t *testing.T) {
	tests := []struct {
		name        string
		req         *pb.CreateEntryRequest
		addFn       func() (*rekor_pb.TransparencyLogEntry, error)
		expectError error
	}{
		{
			name: "valid hashedrekord",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequest{
					HashedRekordRequest: &pb.HashedRekordRequest{
						Signature: []byte("abcd"),
						Verifier: &pb.Verifier{
							Verifier: &pb.Verifier_PublicKey{
								PublicKey: &pb.PublicKey{
									RawBytes: []byte("3456"),
								},
							},
						},
						Data: &v1.HashOutput{
							Digest: []byte("ef12"),
						},
					},
				},
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
		},
		{
			name: "valid dsse",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_DsseRequest{
					DsseRequest: &pb.DSSERequest{
						Envelope: "dsse",
						Verifier: []*pb.Verifier{
							{
								Verifier: &pb.Verifier_PublicKey{
									PublicKey: &pb.PublicKey{
										RawBytes: []byte("3456"),
									},
								},
							},
						},
					},
				},
			},
			addFn: func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
		},
		{
			name: "invalid hashedrekord",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequest{
					HashedRekordRequest: &pb.HashedRekordRequest{},
				},
			},
			addFn:       func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			expectError: fmt.Errorf("invalid hashedrekord request"),
		},
		{
			name: "invalid dsse",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_DsseRequest{
					DsseRequest: &pb.DSSERequest{},
				},
			},
			addFn:       func() (*rekor_pb.TransparencyLogEntry, error) { return &rekor_pb.TransparencyLogEntry{}, nil },
			expectError: fmt.Errorf("invalid dsse request"),
		},
		{
			name: "failed integration",
			req: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequest{
					HashedRekordRequest: &pb.HashedRekordRequest{
						Signature: []byte("abcd"),
						Verifier: &pb.Verifier{
							Verifier: &pb.Verifier_PublicKey{
								PublicKey: &pb.PublicKey{
									RawBytes: []byte("3456"),
								},
							},
						},
						Data: &v1.HashOutput{
							Digest: []byte("ef12"),
						},
					},
				},
			},
			addFn:       func() (*rekor_pb.TransparencyLogEntry, error) { return nil, fmt.Errorf("timed out") },
			expectError: fmt.Errorf("failed to integrate entry"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockStorage{addFn: test.addFn}
			server := NewServer(storage)
			gotTle, gotErr := server.CreateEntry(context.Background(), test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotTle)
			} else {
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

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
	"os"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/pkg/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	ttessera "github.com/transparency-dev/trillian-tessera"
	"google.golang.org/grpc"
)

func TestNewReadServer(t *testing.T) {
	storage := &mockReadStorage{}
	algReg, err := algorithmregistry.AlgorithmRegistry([]string{"ecdsa-sha2-256-nistp256"})
	if err != nil {
		t.Fatal(err)
	}
	server := NewReadServer(storage, false, algReg)
	assert.NoError(t, err)
	assert.NotNil(t, server.storage)
	assert.NotNil(t, server.algorithmRegistry)
}

func TestGetTile(t *testing.T) {
	tests := []struct {
		name        string
		readFn      func() ([]byte, error)
		req         *pb.TileRequest
		expectError error
	}{
		{
			name:   "valid entry bundle request with index and width",
			readFn: func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:    &pb.TileRequest{L: 1, N: "x123/456.p/7"},
		},
		{
			name:   "valid entry bundle request with index",
			readFn: func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:    &pb.TileRequest{L: 1, N: "x123/456"},
		},
		{
			name:        "invalid tile index",
			readFn:      func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:         &pb.TileRequest{L: 0, N: "invalid"},
			expectError: fmt.Errorf("invalid level, index and optional width"),
		},
		{
			name:        "error reading entry bundle",
			readFn:      func() ([]byte, error) { return nil, fmt.Errorf("error") },
			req:         &pb.TileRequest{L: 1, N: "123"},
			expectError: fmt.Errorf("failed to read tile"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockReadStorage{readFn: test.readFn}
			server := NewReadServer(storage, false, nil)
			stream := runtime.ServerTransportStream{} // for gRPC headers
			ctx := grpc.NewContextWithServerTransportStream(context.Background(), &stream)
			gotResp, gotErr := server.GetTile(ctx, test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotResp)
				assert.NotEmpty(t, gotResp.Data)
				assert.Equal(t, gotResp.ContentType, "application/octet-stream")
				vals := stream.Header().Get(httpCacheControlHeader)
				assert.Len(t, vals, 1)
				assert.Equal(t, vals[0], "max-age=31536000, immutable")
			} else {
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

func TestGetEntryBundle(t *testing.T) {
	tests := []struct {
		name        string
		readFn      func() ([]byte, error)
		req         *pb.EntryBundleRequest
		expectError error
	}{
		{
			name:   "valid entry bundle request with index and width",
			readFn: func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:    &pb.EntryBundleRequest{N: "x123/456.p/7"},
		},
		{
			name:   "valid entry bundle request with index",
			readFn: func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:    &pb.EntryBundleRequest{N: "x123/456"},
		},
		{
			name:        "invalid tile index",
			readFn:      func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
			req:         &pb.EntryBundleRequest{N: "invalid"},
			expectError: fmt.Errorf("invalid index and optional width"),
		},
		{
			name:        "error reading entry bundle",
			readFn:      func() ([]byte, error) { return nil, fmt.Errorf("error") },
			req:         &pb.EntryBundleRequest{N: "123"},
			expectError: fmt.Errorf("failed to read entry bundle"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockReadStorage{readFn: test.readFn}
			server := NewReadServer(storage, false, nil)
			stream := runtime.ServerTransportStream{} // for gRPC headers
			ctx := grpc.NewContextWithServerTransportStream(context.Background(), &stream)
			gotResp, gotErr := server.GetEntryBundle(ctx, test.req)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotResp)
				assert.NotEmpty(t, gotResp.Data)
				assert.Equal(t, gotResp.ContentType, "application/octet-stream")
				vals := stream.Header().Get(httpCacheControlHeader)
				assert.Len(t, vals, 1)
				assert.Equal(t, vals[0], "max-age=31536000, immutable")
			} else {
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

func TestGetCheckpoint(t *testing.T) {
	tests := []struct {
		name        string
		readFn      func() ([]byte, error)
		expectError error
	}{
		{
			name:   "valid checkpoint",
			readFn: func() ([]byte, error) { return []byte{1, 2, 3, 4}, nil },
		},
		{
			name:        "error reading checkpoint",
			readFn:      func() ([]byte, error) { return nil, fmt.Errorf("error") },
			expectError: fmt.Errorf("failed to read checkpoint"),
		},
		{
			name:        "no checkpoint",
			readFn:      func() ([]byte, error) { return nil, os.ErrNotExist },
			expectError: fmt.Errorf("checkpoint does not exist"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &mockReadStorage{readFn: test.readFn}
			server := NewReadServer(storage, false, nil)
			stream := runtime.ServerTransportStream{} // for gRPC headers
			ctx := grpc.NewContextWithServerTransportStream(context.Background(), &stream)
			gotResp, gotErr := server.GetCheckpoint(ctx, nil)
			if test.expectError == nil {
				assert.NoError(t, gotErr)
				assert.NotNil(t, gotResp)
				assert.NotEmpty(t, gotResp.Data)
				assert.Equal(t, gotResp.ContentType, "text/plain; charset=utf-8")
				vals := stream.Header().Get(httpCacheControlHeader)
				assert.Len(t, vals, 1)
				assert.Equal(t, vals[0], "no-cache")
			} else {
				assert.ErrorContains(t, gotErr, test.expectError.Error())
			}
		})
	}
}

type mockReadStorage struct {
	readFn func() ([]byte, error)
}

func (s *mockReadStorage) Add(_ context.Context, _ *ttessera.Entry) (*rekor_pb.TransparencyLogEntry, error) {
	return nil, nil
}

func (s *mockReadStorage) ReadTile(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
	return s.readFn()
}

func (s *mockReadStorage) ReadEntryBundle(_ context.Context, _ uint64, _ uint8) ([]byte, error) {
	return s.readFn()
}

func (s *mockReadStorage) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return s.readFn()
}

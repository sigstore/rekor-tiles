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
	"sync"
	"syscall"
	"testing"
	"time"

	pbsc "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// A testing mock that wraps server.Server to Start and defer Stop a server
type MockServer struct {
	gc *GRPCConfig
	hc *HTTPConfig
	wg *sync.WaitGroup
}

func (ms *MockServer) Start(_ *testing.T) {
	ms.gc = NewGRPCConfig()
	ms.hc = NewHTTPConfig()
	s := &mockRekorServer{}

	// Start the server
	ms.wg = &sync.WaitGroup{}
	go func() {
		Serve(context.Background(), ms.hc, ms.gc, s)
		ms.wg.Done()
	}()
	ms.wg.Add(1)

	// TODO: see if health endpoint is up, but for now just wait a second
	time.Sleep(1 * time.Second)
}

func (ms *MockServer) Stop(t *testing.T) {
	// Simulate SIGTERM to trigger graceful shutdown
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Could not kill server")
	}
	ms.wg.Wait()
}

type mockRekorServer struct {
	pb.UnimplementedRekorServer
}

var testEntry = pbs.TransparencyLogEntry{
	LogIndex: 0,
	LogId: &pbsc.LogId{
		KeyId: []byte("abc"),
	},
	KindVersion: &pbs.KindVersion{
		Kind:    "placeholder",
		Version: "1.2.3",
	},
	IntegratedTime:   0,
	InclusionPromise: nil,
	InclusionProof: &pbs.InclusionProof{
		LogIndex: 0,
		RootHash: []byte("abc"),
		TreeSize: 0,
		Hashes:   [][]byte{[]byte("def"), []byte("ghi")},
		Checkpoint: &pbs.Checkpoint{
			Envelope: "placeholder",
		},
	},
	CanonicalizedBody: []byte("abcd"),
}

func (s *mockRekorServer) CreateEntry(_ context.Context, _ *pb.CreateEntryRequest) (*pbs.TransparencyLogEntry, error) {
	return &testEntry, nil
}

func (s *mockRekorServer) GetTile(_ context.Context, in *pb.TileRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-tile:%d,%d", in.L, in.N)),
		Extensions:  nil,
	}, nil
}

func (s *mockRekorServer) GetPartialTile(_ context.Context, in *pb.PartialTileRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-tile:%d,%s,%d", in.L, in.N, in.W)),
		Extensions:  nil,
	}, nil
}

func (s *mockRekorServer) GetEntryBundle(_ context.Context, in *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-entries:%d", in.N)),
		Extensions:  nil,
	}, nil
}
func (s *mockRekorServer) GetPartialEntryBundle(_ context.Context, in *pb.PartialEntryBundleRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-entries:%s,%d", in.N, in.W)),
		Extensions:  nil,
	}, nil
}
func (s *mockRekorServer) GetCheckpoint(_ context.Context, _ *emptypb.Empty) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte("test-checkpoint"),
		Extensions:  nil,
	}, nil
}

func (s mockRekorServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (s mockRekorServer) Watch(_ *grpc_health_v1.HealthCheckRequest, _ grpc_health_v1.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "unimplemented")
}

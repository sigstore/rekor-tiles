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

	pbsc "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/protobuf/types/known/emptypb"
)

type mockServer struct {
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

func (s *mockServer) CreateEntry(_ context.Context, _ *pb.CreateEntryRequest) (*pbs.TransparencyLogEntry, error) {
	return &testEntry, nil
}

func (s *mockServer) GetTile(_ context.Context, in *pb.TileRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-tile:%d,%d", in.L, in.N)),
		Extensions:  nil,
	}, nil
}

func (s *mockServer) GetPartialTile(_ context.Context, in *pb.PartialTileRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-tile:%d,%s,%d", in.L, in.N, in.W)),
		Extensions:  nil,
	}, nil
}

func (s *mockServer) GetEntryBundle(_ context.Context, in *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-entries:%d", in.N)),
		Extensions:  nil,
	}, nil
}
func (s *mockServer) GetPartialEntryBundle(_ context.Context, in *pb.PartialEntryBundleRequest) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-entries:%s,%d", in.N, in.W)),
		Extensions:  nil,
	}, nil
}
func (s *mockServer) GetCheckpoint(_ context.Context, _ *emptypb.Empty) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte("test-checkpoint"),
		Extensions:  nil,
	}, nil
}

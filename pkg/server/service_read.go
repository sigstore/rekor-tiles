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
	"errors"
	"os"
	"strconv"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ReadServer implements the read APIs along with the write APIs
type ReadServer struct {
	Server
}

func NewReadServer(storage tessera.Storage, readOnly bool, algorithmRegistry *signature.AlgorithmRegistryConfig) *ReadServer {
	if readOnly {
		return &ReadServer{
			Server: Server{
				readOnly: readOnly,
				storage:  storage,
			},
		}
	}
	return &ReadServer{
		Server: Server{
			storage:           storage,
			algorithmRegistry: algorithmRegistry,
		},
	}
}

func (s *ReadServer) GetTile(ctx context.Context, req *pb.TileRequest) (*httpbody.HttpBody, error) {
	// Verifies and parses level, index, and optional width for partial tile
	l, i, w, err := layout.ParseTileLevelIndexPartial(strconv.FormatUint(uint64(req.L), 10), req.N)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid level, index and optional width")
	}
	tile, err := s.storage.ReadTile(ctx, l, i, w)
	if err != nil {
		return nil, status.Error(codes.Unknown, "failed to read tile")
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs(httpCacheControlHeader, "max-age=31536000, immutable"))
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        tile,
	}, nil
}

func (s *ReadServer) GetEntryBundle(ctx context.Context, req *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	// Parses index and optional width for partial tile
	i, w, err := layout.ParseTileIndexPartial(req.N)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid index and optional width")
	}
	entryBundle, err := s.storage.ReadEntryBundle(ctx, i, w)
	if err != nil {
		return nil, status.Error(codes.Unknown, "failed to read entry bundle")
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs(httpCacheControlHeader, "max-age=31536000, immutable"))
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        entryBundle,
	}, nil
}

func (s *ReadServer) GetCheckpoint(ctx context.Context, _ *emptypb.Empty) (*httpbody.HttpBody, error) {
	checkpoint, err := s.storage.ReadCheckpoint(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, status.Error(codes.NotFound, "checkpoint does not exist")
		}
		return nil, status.Error(codes.Unknown, "failed to read checkpoint")
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs(httpCacheControlHeader, "no-cache"))
	return &httpbody.HttpBody{
		ContentType: "text/plain; charset=utf-8",
		Data:        checkpoint,
	}, nil
}

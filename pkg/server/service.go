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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/rekor-tiles/pkg/types/dsse"
	"github.com/sigstore/rekor-tiles/pkg/types/hashedrekord"
	ttessera "github.com/transparency-dev/trillian-tessera"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	pb.UnimplementedRekorServer
	storage tessera.Storage
}

func NewServer(storage tessera.Storage) *Server {
	return &Server{
		storage: storage,
	}
}

func (s *Server) CreateEntry(ctx context.Context, req *pb.CreateEntryRequest) (*pbs.TransparencyLogEntry, error) {
	var serialized []byte
	var err error
	var metricsCounter prometheus.Counter
	switch req.GetSpec().(type) {
	case *pb.CreateEntryRequest_HashedRekordRequest:
		hr := req.GetHashedRekordRequest()
		if err := hashedrekord.Validate(hr); err != nil {
			slog.Warn("failed validating hashedrekord request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid hashedrekord request")
		}
		serialized, err = protojson.Marshal(hr)
		if err != nil {
			slog.Warn("failed marshaling hashedrekord request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid hashedrekord request")
		}
		metricsCounter = getMetrics().newHashedRekordEntries
	case *pb.CreateEntryRequest_DsseRequest:
		ds := req.GetDsseRequest()
		if err := dsse.Validate(ds); err != nil {
			slog.Warn("failed validating dsse request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid dsse request")
		}
		serialized, err = protojson.Marshal(ds)
		if err != nil {
			slog.Warn("failed marshaling dsse request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid dsse request")
		}
		metricsCounter = getMetrics().newDsseEntries
	default:
		return nil, status.Errorf(codes.InvalidArgument, "invalid type, must be either hashedrekord or dsse")
	}
	canonicalized, err := jsoncanonicalizer.Transform(serialized)
	if err != nil {
		slog.Warn("failed canonicalizing request", "error", err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "invalid entry")
	}
	entry := ttessera.NewEntry(canonicalized)
	tle, err := s.storage.Add(ctx, entry)
	if err != nil {
		slog.Warn("failed to integrate entry", "error", err.Error())
		return nil, status.Errorf(codes.Unknown, "failed to integrate entry")
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs(httpStatusHeader, "201"))
	metricsCounter.Inc()
	return tle, nil
}

func (s *Server) GetTile(context.Context, *pb.TileRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTile not implemented")
}
func (s *Server) GetPartialTile(context.Context, *pb.PartialTileRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPartialTile not implemented")
}
func (s *Server) GetEntryBundle(context.Context, *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntryBundle not implemented")
}
func (s *Server) GetPartialEntryBundle(context.Context, *pb.PartialEntryBundleRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPartialEntryBundle not implemented")
}
func (s *Server) GetCheckpoint(context.Context, *emptypb.Empty) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCheckpoint not implemented")
}

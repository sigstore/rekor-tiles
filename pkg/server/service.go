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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/rekor-tiles/pkg/types/dsse"
	"github.com/sigstore/rekor-tiles/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore/pkg/signature"
	ttessera "github.com/transparency-dev/trillian-tessera"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

// rekorServer is the collection of methods that our grpc server must implement.
type rekorServer interface {
	pb.RekorServer
	grpc_health_v1.HealthServer
}

type Server struct {
	pb.UnimplementedRekorServer
	grpc_health_v1.UnimplementedHealthServer
	storage           tessera.Storage
	readOnly          bool
	algorithmRegistry *signature.AlgorithmRegistryConfig
	logID             []byte // Non-truncated digest of C2SP signed-note key ID
}

func NewServer(storage tessera.Storage, readOnly bool, algorithmRegistry *signature.AlgorithmRegistryConfig, logID []byte) *Server {
	if readOnly {
		return &Server{
			readOnly: readOnly,
			logID:    logID,
		}
	}
	return &Server{
		storage:           storage,
		algorithmRegistry: algorithmRegistry,
		logID:             logID,
	}
}

func (s *Server) CreateEntry(ctx context.Context, req *pb.CreateEntryRequest) (*pbs.TransparencyLogEntry, error) {
	if s.readOnly {
		slog.Warn("rekor is in read-only mode, cannot create new entry")
		_ = grpc.SetHeader(ctx, metadata.Pairs(httpStatusCodeHeader, "405"))
		_ = grpc.SetHeader(ctx, metadata.Pairs(httpErrorMessageHeader, "This log has been frozen, please switch to the latest log."))
		return nil, status.Errorf(codes.Unimplemented, "log frozen")
	}
	var serialized []byte
	var err error
	var metricsCounter prometheus.Counter
	var kv *pbs.KindVersion
	switch req.GetSpec().(type) {
	case *pb.CreateEntryRequest_HashedRekordRequestV0_0_2:
		hr := req.GetHashedRekordRequestV0_0_2()
		entry, err := hashedrekord.ToLogEntry(hr, s.algorithmRegistry)
		if err != nil {
			slog.Warn("failed validating hashedrekord request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid hashedrekord request")
		}
		kv = &pbs.KindVersion{
			Kind:    entry.Kind,
			Version: entry.ApiVersion,
		}
		serialized, err = protojson.Marshal(entry)
		if err != nil {
			slog.Warn("failed marshaling hashedrekord request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid hashedrekord request")
		}
		metricsCounter = getMetrics().newHashedRekordEntries
	case *pb.CreateEntryRequest_DsseRequestV0_0_2:
		ds := req.GetDsseRequestV0_0_2()
		entry, err := dsse.ToLogEntry(ds, s.algorithmRegistry)
		if err != nil {
			slog.Warn("failed validating dsse request", "error", err.Error())
			return nil, status.Errorf(codes.InvalidArgument, "invalid dsse request")
		}
		kv = &pbs.KindVersion{
			Kind:    entry.Kind,
			Version: entry.ApiVersion,
		}
		serialized, err = protojson.Marshal(entry)
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
	if errors.As(err, &tessera.DuplicateError{}) {
		return nil, status.Error(codes.AlreadyExists, err.Error())
	}
	if errors.As(err, &tessera.InclusionProofVerificationError{}) {
		getMetrics().inclusionProofFailureCount.Inc()
	}
	if err != nil {
		slog.Warn("failed to integrate entry", "error", err.Error())
		return nil, status.Errorf(codes.Unknown, "failed to integrate entry")
	}
	// Set bundle's kind and version, which clients that do not persist the
	// canonicalized body will use to reconstruct the entry leaf hash
	tle.KindVersion = kv
	// Set log ID, to be used by clients to look up the corresponding instance
	// in a trust root. Will be removed in the future, as clients should use
	// the checkpoint's key ID as a unique log identifier.
	tle.LogId = &v1.LogId{KeyId: s.logID}

	_ = grpc.SetHeader(ctx, metadata.Pairs(httpStatusCodeHeader, "201"))
	metricsCounter.Inc()
	return tle, nil
}

func (s *Server) GetTile(context.Context, *pb.TileRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTile not implemented")
}
func (s *Server) GetEntryBundle(context.Context, *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntryBundle not implemented")
}
func (s *Server) GetCheckpoint(context.Context, *emptypb.Empty) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCheckpoint not implemented")
}

// Check implements the Healthcheck protocol to report the health of the service.
// See https://grpc-ecosystem.github.io/grpc-gateway/docs/operations/health_check/.
func (s Server) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

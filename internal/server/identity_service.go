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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/identity"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/proof"
	ttessera "github.com/transparency-dev/tessera"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type IdentityServer struct {
	pb.UnimplementedIdentityRekorServer
	grpc_health_v1.UnimplementedHealthServer
	storage           tessera.Storage
	readOnly          bool
	logID             []byte
	algorithmRegistry *signature.AlgorithmRegistryConfig
}

func NewIdentityServer(storage tessera.Storage, readOnly bool, algorithmRegistry *signature.AlgorithmRegistryConfig, logID []byte) *IdentityServer {
	return &IdentityServer{
		storage:           storage,
		readOnly:          readOnly,
		logID:             logID,
		algorithmRegistry: algorithmRegistry,
	}
}

func (s *IdentityServer) CreateEntry(ctx context.Context, req *pb.IdentityRequestV001) (*httpbody.HttpBody, error) {
	if s.readOnly {
		slog.WarnContext(ctx, "rekor is in read-only mode, cannot create new entry")
		_ = grpc.SetHeader(ctx, metadata.Pairs(httpStatusCodeHeader, "405"))
		_ = grpc.SetHeader(ctx, metadata.Pairs(httpErrorMessageHeader, "This log has been frozen, please switch to the latest log."))
		return nil, status.Errorf(codes.Unimplemented, "log frozen")
	}

	leafBytes, err := identity.ToLogEntry(req)
	if err != nil {
		slog.WarnContext(ctx, "failed validating identity request", "error", err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "invalid identity request")
	}

	entry := ttessera.NewEntry(leafBytes)
	tle, err := s.storage.Add(ctx, entry)
	if errors.Is(err, ttessera.ErrPushback) {
		return nil, status.Errorf(codes.Unavailable, "reached max pushback; retry")
	}
	if errors.Is(err, context.Canceled) {
		return nil, status.Error(codes.Canceled, err.Error())
	}
	var dupErr tessera.DuplicateError
	if errors.As(err, &dupErr) {
		_ = grpc.SetHeader(ctx, metadata.Pairs(
			duplicateEntryHeader,
			strconv.FormatUint(dupErr.Index(), 10)))
		return nil, status.Error(codes.AlreadyExists, err.Error())
	}
	if errors.As(err, &tessera.InclusionProofVerificationError{}) {
		getMetrics().inclusionProofFailureCount.Inc()
	}
	if err != nil {
		slog.WarnContext(ctx, "failed to integrate entry", "error", err.Error())
		return nil, status.Errorf(codes.Unknown, "failed to integrate entry")
	}

	_ = grpc.SetHeader(ctx, metadata.Pairs(httpStatusCodeHeader, "201"))
	getMetrics().newIdentityEntries.Inc()

	var proofHashes [][32]byte
	for _, h := range tle.InclusionProof.Hashes {
		var arr [32]byte
		copy(arr[:], h)
		proofHashes = append(proofHashes, arr)
	}

	var extraData []byte
	if len(req.GetContext()) > 0 {
		var contextPairs []string
		for _, entry := range req.GetContext() {
			k := hex.EncodeToString(entry.GetKey())
			v := hex.EncodeToString(entry.GetValue())
			contextPairs = append(contextPairs, fmt.Sprintf("%s:%s", k, v))
		}
		extraData = []byte(strings.Join(contextPairs, "\n"))
	}

	p := proof.TLogProof{
		//nolint:gosec
		Index:      uint64(tle.InclusionProof.LogIndex),
		Hashes:     proofHashes,
		Checkpoint: []byte(tle.InclusionProof.Checkpoint.Envelope),
		ExtraData:  extraData,
	}
	proofBytes := p.Marshal()

	return &httpbody.HttpBody{
		ContentType: "text/plain",
		Data:        proofBytes,
	}, nil
}

func (s *IdentityServer) GetTile(context.Context, *pb.TileRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTile not implemented")
}

func (s *IdentityServer) GetEntryBundle(context.Context, *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntryBundle not implemented")
}

func (s *IdentityServer) GetCheckpoint(context.Context, *emptypb.Empty) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCheckpoint not implemented")
}

// Check implements the Healthcheck protocol to report the health of the service.
func (s IdentityServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

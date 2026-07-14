// Copyright 2026 The Sigstore Authors
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

	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type IdentityServer struct {
	pb.UnimplementedIdentityRekorServer
	grpc_health_v1.UnimplementedHealthServer
	storage           tessera.Storage
	readOnly          bool
	algorithmRegistry *signature.AlgorithmRegistryConfig
}

func NewIdentityServer(storage tessera.Storage, readOnly bool, algorithmRegistry *signature.AlgorithmRegistryConfig) *IdentityServer {
	return &IdentityServer{
		storage:           storage,
		readOnly:          readOnly,
		algorithmRegistry: algorithmRegistry,
	}
}

func (s *IdentityServer) CreateEntry(_ context.Context, _ *pb.IdentityRequestV001) (*httpbody.HttpBody, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEntry not implemented")
}

// Check implements the Healthcheck protocol to report the health of the service.
func (s IdentityServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

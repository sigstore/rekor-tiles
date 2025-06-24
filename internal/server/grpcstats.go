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
	"strings"

	"google.golang.org/grpc/stats"
)

// GrpcStatsHandler consumes grpc stats and converts them to metrics
type GrpcStatsHandler struct{}

func (st *GrpcStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	// this is a no-op we don't care about connections for now
	return ctx
}

func (st *GrpcStatsHandler) HandleConn(_ context.Context, _ stats.ConnStats) {
	// this is a no-op we don't care about connections for now
}

type rpcStatCtxKey struct{}

func (st *GrpcStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	// add the rpc info to the context so we can access the method name later
	return context.WithValue(ctx, rpcStatCtxKey{}, info)
}

// HandleRPC processes the RPC stats. Note: All stat fields are read-only.
func (st *GrpcStatsHandler) HandleRPC(ctx context.Context, stat stats.RPCStats) {
	info, ok := ctx.Value(rpcStatCtxKey{}).(*stats.RPCTagInfo)
	if !ok {
		return
	}
	service, method := splitFullMethodName(info.FullMethodName)
	switch t := stat.(type) {
	case *stats.InPayload:
		size := t.WireLength
		getMetrics().grpcRequestSize.WithLabelValues(service, method, "payload").Observe(float64(size))
	default:
		// do nothing
	}
}

func NewGrpcStatsHandler() *GrpcStatsHandler {
	return &GrpcStatsHandler{}
}

// splitFullMethodName returns the service and method name of the RPC.
func splitFullMethodName(fullMethod string) (string, string) {
	fullMethod = strings.TrimPrefix(fullMethod, "/") // remove leading slash
	if i := strings.Index(fullMethod, "/"); i >= 0 {
		return fullMethod[:i], fullMethod[i+1:]
	}
	return "unknown", "unknown"
}

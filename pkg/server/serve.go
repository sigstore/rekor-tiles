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
	"os"
	"sync"
)

// Serve starts the grpc server and its http proxy.
func Serve(ctx context.Context, hc *HTTPConfig, gc *GRPCConfig, s grpcServerI) {
	var wg sync.WaitGroup

	if hc.port == 0 || gc.port == 0 {
		slog.Error("dynamic port allocation '0' is not supported", "http port", hc.port, "grpc port", gc.port)
		os.Exit(1)
	}
	if hc.port == gc.port && hc.host == gc.host {
		slog.Error("http and grpc cannot serve at the same address", "host", hc.host, "port", hc.port)
		os.Exit(1)
	}

	grpcServer := newGRPCService(gc, s)
	grpcServer.start(&wg)

	httpProxy := newHTTPProxy(ctx, hc, grpcServer)
	httpProxy.start(&wg)

	wg.Wait()
}

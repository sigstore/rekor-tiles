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
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type grpcServer struct {
	*grpc.Server
	serverEndpoint string
}

// newGRPCServer starts a new grpc server and registers the services.
func newGRPCServer(config *GRPCConfig, server rekorServer) *grpcServer {
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(getMetrics().serverMetrics.UnaryServerInterceptor()))
	pb.RegisterRekorServer(s, server)
	grpc_health_v1.RegisterHealthServer(s, server)

	getMetrics().serverMetrics.InitializeMetrics(s)

	return &grpcServer{s, fmt.Sprintf("%s:%v", config.host, config.port)}
}

func (gs *grpcServer) start(wg *sync.WaitGroup) {

	slog.Info("starting grpc Server", "address", gs.serverEndpoint)

	lis, err := net.Listen("tcp", gs.serverEndpoint)
	if err != nil {
		slog.Error("Failed to create listener:", "errors", err)
		os.Exit(1)
	}

	// update the endpoint to standardize
	gs.serverEndpoint = lis.Addr().String()

	waitToClose := make(chan struct{})
	go func() {
		// capture interrupts and shutdown Server
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		gs.GracefulStop()
		close(waitToClose)
		slog.Info("stopped grpc Server")
	}()

	wg.Add(1)
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("error shutting down grpc Server", "errors", err)
			os.Exit(1)
		}
		<-waitToClose
		wg.Done()
		slog.Info("grpc Server shutdown")
	}()
}

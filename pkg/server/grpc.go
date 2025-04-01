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
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type grpcServer struct {
	*grpc.Server
	serverEndpoint string
}

// newGRPCServer starts a new grpc server and registers the services.
func newGRPCServer(config *GRPCConfig, server rekorServer) *grpcServer {
	var opts []grpc.ServerOption

	opts = append(opts, grpc.ChainUnaryInterceptor(
		getMetrics().serverMetrics.UnaryServerInterceptor(),
	))

	if config.HasTLS() {
		creds, err := loadTLSCredentials(config.certFile, config.keyFile)
		if err != nil {
			slog.Error("failed to load TLS credentials", "error", err)
			os.Exit(1)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	s := grpc.NewServer(opts...)
	pb.RegisterRekorServer(s, server)
	grpc_health_v1.RegisterHealthServer(s, server)

	getMetrics().serverMetrics.InitializeMetrics(s)

	return &grpcServer{
		Server:         s,
		serverEndpoint: config.GRPCTarget(),
	}
}

func (gs *grpcServer) start(wg *sync.WaitGroup) {
	slog.Info("Starting gRPC server", "address", gs.serverEndpoint)

	lis, err := net.Listen("tcp", gs.serverEndpoint)
	if err != nil {
		slog.Error("failed to create listener:", "error", err)
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
		slog.Info("stopped gRPC server")
	}()

	wg.Add(1)
	go func() {
		if err := gs.Serve(lis); err != nil {
			slog.Error("error shutting down gRPC server", "error", err)
			os.Exit(1)
		}
		<-waitToClose
		wg.Done()
		slog.Info("gRPC Server shutdown")
	}()
}

func loadTLSCredentials(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsConfig), nil
}

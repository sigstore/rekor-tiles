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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const httpStatusHeader = "x-http-code"

type httpProxy struct {
	*http.Server
	serverEndpoint string
}

func newHTTPProxy(ctx context.Context, config *HTTPConfig, grpcServer *grpcServer) *httpProxy {
	// configure a custom marshaler to fail on unknown fields
	strictMarshaler := runtime.HTTPBodyMarshaler{
		Marshaler: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				EmitUnpopulated: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: false,
			},
		},
	}
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &strictMarshaler),
		runtime.WithForwardResponseOption(httpResponseModifier),
	)

	// TODO: allow TLS if the startup provides a TLS cert, but for now the proxy connects to grpc without TLS
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	err := pb.RegisterRekorHandlerFromEndpoint(ctx, mux, grpcServer.serverEndpoint, opts)
	if err != nil {
		slog.Error("Failed to register gateway:", "errors", err)
		os.Exit(1)
	}

	// TODO: configure https connection preferences (time-out, max size, etc)

	endpoint := fmt.Sprintf("%s:%v", config.host, config.port)
	return &httpProxy{
		Server: &http.Server{
			Addr:    endpoint,
			Handler: mux,

			ReadTimeout:       60 * time.Second,
			ReadHeaderTimeout: 60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       config.idleTimeout,
		},
		serverEndpoint: endpoint,
	}
}

func (hp *httpProxy) start(wg *sync.WaitGroup) {

	lis, err := net.Listen("tcp", hp.serverEndpoint)
	if err != nil {
		slog.Error("failed to create listener:", "errors", err)
		os.Exit(1)
	}

	hp.serverEndpoint = lis.Addr().String()

	slog.Info("starting http proxy", "address", hp.serverEndpoint)

	waitToClose := make(chan struct{})
	go func() {
		// capture interrupts and shutdown Server
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		if err := hp.Shutdown(context.Background()); err != nil {
			slog.Info("http Server Shutdown error", "errors", err)
		}
		close(waitToClose)
		slog.Info("stopped http Server")
	}()

	wg.Add(1)
	go func() {

		if err := hp.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("could not start http server", "errors", err)
			os.Exit(1)
		}
		<-waitToClose
		wg.Done()
		slog.Info("http Server shutdown")
	}()
}

func httpResponseModifier(ctx context.Context, w http.ResponseWriter, _ proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	// set http status code
	if vals := md.HeaderMD.Get(httpStatusHeader); len(vals) > 0 {
		code, err := strconv.Atoi(vals[0])
		if err != nil {
			return err
		}
		// delete the headers to not expose any grpc-metadata in http response
		delete(md.HeaderMD, httpStatusHeader)
		delete(w.Header(), "Grpc-Metadata-X-Http-Code")
		w.WriteHeader(code)
	}

	return nil
}

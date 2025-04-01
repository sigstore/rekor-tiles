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
	"crypto/tls"
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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
)

const httpStatusHeader = "x-http-code"

type httpProxy struct {
	*http.Server
	serverEndpoint string
}

// newHTTProxy creates a mux for each of the service grpc methods, including the grpc heatlhcheck.
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

	var opts []grpc.DialOption
	if config.HasTLS() {
		creds, err := credentials.NewClientTLSFromFile(config.certFile, "")
		if err != nil {
			slog.Error("failed to create TLS credentials", "errors", err)
			os.Exit(1)
		}
		opts = []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	} else {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}

	// GRPC client connection so the http mux's healthz endpoint can reach the grpc healthcheck service.
	// See https://grpc-ecosystem.github.io/grpc-gateway/docs/operations/health_check/#adding-healthz-endpoint-to-runtimeservemux.
	cc, err := grpc.NewClient(grpcServer.serverEndpoint, opts...)
	if err != nil {
		slog.Error("failed to connect to grpc server:", "errors", err)
		os.Exit(1)
	}
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &strictMarshaler),
		runtime.WithForwardResponseOption(httpResponseModifier),
		runtime.WithHealthzEndpoint(grpc_health_v1.NewHealthClient(cc)), // localhost:[port]/healthz
	)

	err = pb.RegisterRekorHandlerFromEndpoint(ctx, mux, grpcServer.serverEndpoint, opts)
	if err != nil {
		slog.Error("failed to register gateway:", "errors", err)
		os.Exit(1)
	}

	metrics := getMetrics()
	handler := promhttp.InstrumentMetricHandler(metrics.reg, mux)
	handler = promhttp.InstrumentHandlerDuration(metrics.httpLatency, handler)
	handler = promhttp.InstrumentHandlerCounter(metrics.httpRequestsCount, handler)
	handler = promhttp.InstrumentHandlerRequestSize(metrics.requestSize, handler)
	handler = http.MaxBytesHandler(handler, int64(config.maxSizeBytes))

	// TODO: configure https connection preferences (time-out, max size, etc)
	server := &http.Server{
		Addr:              config.HTTPTarget(),
		Handler:           handler,
		ReadTimeout:       config.timeout,
		ReadHeaderTimeout: config.timeout,
		WriteTimeout:      config.timeout,
		IdleTimeout:       config.timeout,
	}

	if config.HasTLS() {
		cert, err := tls.LoadX509KeyPair(config.certFile, config.keyFile)
		if err != nil {
			slog.Error("failed to load TLS certificates:", "errors", err)
			os.Exit(1)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	return &httpProxy{
		Server:         server,
		serverEndpoint: config.HTTPTarget(),
	}
}

func (hp *httpProxy) start(wg *sync.WaitGroup) {
	lis, err := net.Listen("tcp", hp.serverEndpoint)
	if err != nil {
		slog.Error("failed to create listener:", "errors", err)
		os.Exit(1)
	}

	hp.serverEndpoint = lis.Addr().String()

	var protocol string
	if hp.TLSConfig != nil {
		protocol = "HTTPS"
		slog.Info("starting HTTPS proxy", "address", hp.serverEndpoint)
	} else {
		protocol = "HTTP"
		slog.Info("starting HTTP proxy", "address", hp.serverEndpoint)
	}

	waitToClose := make(chan struct{})
	go func() {
		// capture interrupts and shutdown Server
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		if err := hp.Shutdown(context.Background()); err != nil {
			slog.Info("http server shutdown errors:", "error", err)
		}
		close(waitToClose)
		slog.Info(fmt.Sprintf("Stopped %s server", protocol))
	}()

	wg.Add(1)
	go func() {
		var err error
		if hp.TLSConfig != nil {
			err = hp.ServeTLS(lis, "", "") // skip cert and key as they are already set in TLSConfig
		} else {
			err = hp.Serve(lis)
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error(fmt.Sprintf("could not start %s server:", protocol), "error", err)
			os.Exit(1)
		}
		<-waitToClose
		wg.Done()
		slog.Info(fmt.Sprintf("%s server shutdown complete", protocol))
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

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
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"google.golang.org/grpc/reflection"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/release-utils/version"
)

type metrics struct {
	reg           *prometheus.Registry
	serverMetrics *grpc_prometheus.ServerMetrics
	// metrics
	newHashedRekordEntries     prometheus.Counter
	newDsseEntries             prometheus.Counter
	httpLatency                *prometheus.HistogramVec
	httpRequestsCount          *prometheus.CounterVec
	httpRequestSize            *prometheus.HistogramVec
	panicsTotal                prometheus.Counter
	inclusionProofFailureCount prometheus.Counter
	grpcRequestSize            *prometheus.HistogramVec
}

// Metrics provides the singleton metrics instance
func getMetrics() *metrics {
	return _initMetricsFunc()
}

var _initMetricsFunc = sync.OnceValue[*metrics](func() *metrics {
	m := metrics{
		reg:           prometheus.NewRegistry(),
		serverMetrics: grpc_prometheus.NewServerMetrics(grpc_prometheus.WithServerHandlingTimeHistogram()),
	}
	m.reg.MustRegister(m.serverMetrics)

	f := promauto.With(m.reg)

	m.newHashedRekordEntries = f.NewCounter(prometheus.CounterOpts{
		Name: "rekor_v2_new_hashedrekord_entries",
		Help: "The total number of new dsse log entries",
	})

	m.newDsseEntries = f.NewCounter(prometheus.CounterOpts{
		Name: "rekor_v2_new_dsse_entries",
		Help: "The total number of new dsse log entries",
	})

	// grpc_packet_part should always be "payload" but we can measure "header" or "trailer" in the future
	// if we so desire
	m.grpcRequestSize = f.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rekor_v2_grpc_api_request_size",
		Help: "API Request size on GRPC calls",
	}, []string{"grpc_service", "grpc_method", "grpc_packet_part"})

	m.httpLatency = f.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rekor_v2_http_api_latency",
		Help: "API Latency on HTTP calls",
	}, []string{"code", "method"})

	m.httpRequestsCount = f.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_v2_http_requests_total",
		Help: "Count all HTTP requests",
	}, []string{"code", "method"})

	m.httpRequestSize = f.NewHistogramVec(prometheus.HistogramOpts{
		Name: "rekor_v2_http_api_request_size",
		Help: "API Request size on HTTP calls",
	}, []string{"code", "method"})

	m.panicsTotal = f.NewCounter(prometheus.CounterOpts{
		Name: "rekor_v2_grpc_req_panics_recovered_total",
		Help: "Total number of gRPC requests recovered from internal panic.",
	})

	m.inclusionProofFailureCount = f.NewCounter(prometheus.CounterOpts{
		Name: "rekor_v2_inclusion_proof_failure_total",
		Help: "Total number of inclusion proof verification failures, which should always be zero. Likely catastrophic failure if not zero.",
	})

	_ = f.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "rekor_v2",
			Name:      "build_info",
			Help:      "A metric with a constant '1' value labeled by version, revision, branch, and goversion from which rekor was built.",
			ConstLabels: prometheus.Labels{
				"version":    version.GetVersionInfo().GitVersion,
				"revision":   version.GetVersionInfo().GitCommit,
				"build_date": version.GetVersionInfo().BuildDate,
				"goversion":  version.GetVersionInfo().GoVersion,
			},
		},
		func() float64 { return 1 },
	)
	return &m
})

type httpMetrics struct {
	*http.Server
	serverEndpoint string
}

func newHTTPMetrics(_ context.Context, config *HTTPConfig) *httpMetrics {
	mux := http.NewServeMux()
	mux.Handle("/", promhttp.HandlerFor(getMetrics().reg, promhttp.HandlerOpts{
		Timeout: config.timeout,
	}))

	endpoint := config.HTTPMetricsTarget()
	return &httpMetrics{
		Server: &http.Server{
			Addr:    endpoint,
			Handler: mux,

			ReadTimeout:       config.timeout,
			ReadHeaderTimeout: config.timeout,
			WriteTimeout:      config.timeout,
			IdleTimeout:       config.timeout,
		},
		serverEndpoint: endpoint,
	}
}

func (hp *httpMetrics) start(wg *sync.WaitGroup) {

	lis, err := net.Listen("tcp", hp.serverEndpoint)
	if err != nil {
		slog.Error("failed to create listener:", "errors", err)
		os.Exit(1)
	}

	hp.serverEndpoint = lis.Addr().String()

	slog.Info("starting http metrics", "address", hp.serverEndpoint)

	waitToClose := make(chan struct{})
	go func() {
		// capture interrupts and shutdown Server
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		if err := hp.Shutdown(context.Background()); err != nil {
			slog.Info("http metrics Server Shutdown error", "errors", err)
		}
		close(waitToClose)
		slog.Info("stopped http metrics Server")
	}()

	wg.Add(1)
	go func() {

		if err := hp.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("could not start http metrics server", "errors", err)
			os.Exit(1)
		}
		<-waitToClose
		wg.Done()
		slog.Info("http metrics Server shutdown")
	}()
}

// InitializeCustomGrpcMetrics mirrors the functionality of prometheus.ServerMetrics InitializeMetrics but for our own
// custom grpc metrics
func (m *metrics) InitializeCustomGrpcMetrics(server reflection.ServiceInfoProvider) {
	serviceInfo := server.GetServiceInfo()
	for serviceName, info := range serviceInfo {
		for _, mInfo := range info.Methods {
			methodName := mInfo.Name
			// These are just references (no increments), as just referencing will create the labels but not set values.
			_, _ = m.grpcRequestSize.GetMetricWithLabelValues(serviceName, methodName, "payload")
		}
	}
}

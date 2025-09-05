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
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestServe_httpMetricsSmoke(t *testing.T) {
	// To debug set slog to output to stdout
	// slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	server := MockServer{}
	server.Start(t)
	defer server.Stop(t)

	// Check if we can hit the metrics endpoint
	metricsURL := fmt.Sprintf("http://%s", server.hc.HTTPMetricsTarget())

	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("fetching metrics from %s, %v", metricsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("%s: got %d want %d", metricsURL, resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	b := string(body)

	// we ping healthz in our MockServer that will initialize some http stats for us. On a raw
	// server with no requests ever recorded, rekor_http_* statistics may be uninitialized
	expectedMetrics := []string{
		"rekor_v2_new_hashedrekord_entries",
		"rekor_v2_new_dsse_entries",
		"build_info",
		"rekor_v2_http_api_latency",
		"rekor_v2_http_requests_total",
		"rekor_v2_http_api_request_size",
		"rekor_v2_grpc_req_panics_recovered_total",
		"rekor_v2_grpc_api_request_size",
		"grpc_server_started_total",    // should imply we have the default set of grpc server metrics
		"grpc_server_handling_seconds", // should imply we have the default set of latency stats on grpc servers
		"promhttp_metric_handler",      // should imply we have the default set of promhttp metrics
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(b, metric) {
			t.Errorf("metrics target body did not contain %s, \n %s", metric, body)
		}
	}
}

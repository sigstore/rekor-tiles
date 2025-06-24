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
	"testing"
	"time"
)

func TestNewHTTPConfig(t *testing.T) {
	// Test default configuration
	config := NewHTTPConfig()
	if config.host != "localhost" {
		t.Errorf("expected host to be localhost, got %s", config.host)
	}
	if config.timeout != 60*time.Second {
		t.Errorf("expected idleTimeout to be 60s, got %v", config.timeout)
	}
	if config.maxRequestBodySize != 4*1024*1024 {
		t.Errorf("expected maxSize)} to be 4MB, got %d", config.maxRequestBodySize)
	}
	if config.port != 8080 {
		t.Errorf("expected port to be 8080, got %d", config.port)
	}
	if config.metricsPort != 2112 {
		t.Errorf("expected metricsport to be 2112, got %d", config.port)
	}
	if config.HTTPTarget() != "localhost:8080" {
		t.Errorf("expected http target to be localhost:8080, got %s", config.HTTPTarget())
	}
	if config.HTTPMetricsTarget() != "localhost:2112" {
		t.Errorf("expected http metrics target to be localhost:2112, got %s", config.HTTPTarget())
	}
}

func TestWithHTTPPort(t *testing.T) {
	config := NewHTTPConfig(WithHTTPPort(9000))
	if config.port != 9000 {
		t.Errorf("expected port to be 9000, got %d", config.port)
	}
}

func TestWithHTTPHost(t *testing.T) {
	config := NewHTTPConfig(WithHTTPHost("example.com"))
	if config.host != "example.com" {
		t.Errorf("expected host to be example.com, got %s", config.host)
	}
}

func TestWithHTTTimeout(t *testing.T) {
	config := NewHTTPConfig(WithHTTPTimeout(30 * time.Second))
	if config.timeout != 30*time.Second {
		t.Errorf("expected idleTimeout to be 30s, got %v", config.timeout)
	}
}

func TestWithHTTPMaxRequestBodySize(t *testing.T) {
	config := NewHTTPConfig(WithHTTPMaxRequestBodySize(2 * 1024 * 1024))
	if config.maxRequestBodySize != 2*1024*1024 {
		t.Errorf("expected maxSize to be) 2MB, got %d", config.maxRequestBodySize)
	}
}

func TestWithHTTPMetricsPort(t *testing.T) {
	config := NewHTTPConfig(WithHTTPMetricsPort(9001))
	if config.metricsPort != 9001 {
		t.Errorf("expected metrics port to be 9001, got %d", config.port)
	}
}

func TestMultipleOptions(t *testing.T) {
	config := NewHTTPConfig(
		WithHTTPPort(9090),
		WithHTTPHost("test.example.com"),
		WithHTTPTimeout(10*time.Second),
		WithHTTPMaxRequestBodySize(1*1024*1024),
		WithHTTPMetricsPort(9091),
	)
	if config.port != 9090 {
		t.Errorf("expected port to be 9090, got %d", config.port)
	}
	if config.metricsPort != 9091 {
		t.Errorf("expected port to be 9091, got %d", config.port)
	}
	if config.host != "test.example.com" {
		t.Errorf("expected host to be test.example.com, got %s", config.host)
	}
	if config.timeout != 10*time.Second {
		t.Errorf("expected idleTimeout to be 10s, got %v", config.timeout)
	}
	if config.maxRequestBodySize != 1*1024*1024 {
		t.Errorf("expected maxSize to be 1MB, got %d", config.maxRequestBodySize)
	}
	if config.HTTPTarget() != "test.example.com:9090" {
		t.Errorf("expected http target to be test.example.com:9090, got %s", config.HTTPTarget())
	}
	if config.HTTPMetricsTarget() != "test.example.com:9091" {
		t.Errorf("expected http metrics target to be test.example.com:9091, got %s", config.HTTPTarget())
	}
}
func TestWithHTTPTLSCredentials(t *testing.T) {
	config := NewHTTPConfig(WithHTTPTLSCredentials("cert.pem", "key.pem"))
	if config.certFile != "cert.pem" {
		t.Errorf("expected certFile to be cert.pem, got %s", config.certFile)
	}
	if config.keyFile != "key.pem" {
		t.Errorf("expected keyFile to be key.pem, got %s", config.keyFile)
	}
	if !config.HasTLS() {
		t.Error("expected HasTLS to return true when TLS credentials are set")
	}
}

func TestHasTLS(t *testing.T) {
	config := NewHTTPConfig()
	if config.HasTLS() {
		t.Error("expected HasTLS to return false when no TLS credentials are set")
	}

	config = NewHTTPConfig(func(c *HTTPConfig) { c.certFile = "cert.pem" })
	if config.HasTLS() {
		t.Error("expected HasTLS to return false when only certFile is set")
	}

	config = NewHTTPConfig(func(c *HTTPConfig) { c.keyFile = "key.pem" })
	if config.HasTLS() {
		t.Error("expected HasTLS to return false when only keyFile is set")
	}

	config = NewHTTPConfig(WithHTTPTLSCredentials("cert.pem", "key.pem"))
	if !config.HasTLS() {
		t.Error("expected HasTLS to return true when both certFile and keyFile are set")
	}
}

func TestWithGRPCTLSCredentials(t *testing.T) {
	config := NewHTTPConfig()
	if config.HasGRPCTLS() {
		t.Error("expected HasGRPCTLS to return false when no gRPC TLS credentials are set")
	}

	config = NewHTTPConfig(WithGRPCTLSCredentials("cert.pem"))
	if config.grpcCertFile != "cert.pem" {
		t.Errorf("expected gRPC cert file to be cert.pem, got %s", config.certFile)
	}
	if !config.HasGRPCTLS() {
		t.Error("expected HasGRPCTLS to return true when both certFile and keyFile are set")
	}
}

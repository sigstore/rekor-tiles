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
		t.Errorf("Expected host to be localhost, got %s", config.host)
	}
	if config.idleTimeout != 60*time.Second {
		t.Errorf("Expected idleTimeout to be 60s, got %v", config.idleTimeout)
	}
	if config.port != 8080 {
		t.Errorf("Expected port to be 8080, got %d", config.port)
	}
	if config.metricsPort != 2112 {
		t.Errorf("Expected metricsport to be 2112, got %d", config.port)
	}
	if config.HTTPTarget() != "localhost:8080" {
		t.Errorf("Expected http target to be localhost:8080, got %s", config.HTTPTarget())
	}
	if config.HTTPMetricsTarget() != "localhost:2112" {
		t.Errorf("Expected http metrics target to be localhost:2112, got %s", config.HTTPTarget())
	}
}

func TestWithHTTPPort(t *testing.T) {
	config := NewHTTPConfig(WithHTTPPort(9000))
	if config.port != 9000 {
		t.Errorf("Expected port to be 9000, got %d", config.port)
	}
}

func TestWithHTTPHost(t *testing.T) {
	config := NewHTTPConfig(WithHTTPHost("example.com"))
	if config.host != "example.com" {
		t.Errorf("Expected host to be example.com, got %s", config.host)
	}
}

func TestWithHTTPIdleTimeout(t *testing.T) {
	config := NewHTTPConfig(WithHTTPIdleTimeout(30 * time.Second))
	if config.idleTimeout != 30*time.Second {
		t.Errorf("Expected idleTimeout to be 30s, got %v", config.idleTimeout)
	}
}

func TestWithHTTPMetricsPort(t *testing.T) {
	config := NewHTTPConfig(WithHTTPMetricsPort(9001))
	if config.metricsPort != 9001 {
		t.Errorf("Expected metrics port to be 9001, got %d", config.port)
	}
}

func TestMultipleOptions(t *testing.T) {
	config := NewHTTPConfig(
		WithHTTPPort(9090),
		WithHTTPHost("test.example.com"),
		WithHTTPIdleTimeout(10*time.Second),
		WithHTTPMetricsPort(9091),
	)
	if config.port != 9090 {
		t.Errorf("Expected port to be 9090, got %d", config.port)
	}
	if config.metricsPort != 9091 {
		t.Errorf("Expected port to be 9091, got %d", config.port)
	}
	if config.host != "test.example.com" {
		t.Errorf("Expected host to be test.example.com, got %s", config.host)
	}
	if config.idleTimeout != 10*time.Second {
		t.Errorf("Expected idleTimeout to be 10s, got %v", config.idleTimeout)
	}
	if config.HTTPTarget() != "test.example.com:9090" {
		t.Errorf("Expected http target to be test.example.com:9090, got %s", config.HTTPTarget())
	}
	if config.HTTPMetricsTarget() != "test.example.com:9091" {
		t.Errorf("Expected http metrics target to be test.example.com:9091, got %s", config.HTTPTarget())
	}
}

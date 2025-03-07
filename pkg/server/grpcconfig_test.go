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
)

func TestNewGRPCConfig(t *testing.T) {
	// Test default configuration
	config := NewGRPCConfig()
	if config.host != "localhost" {
		t.Errorf("Expected host to be localhost, got %s", config.host)
	}
	if config.port != 8081 {
		t.Errorf("Expected port to be 8081, got %d", config.port)
	}
}

func TestWithGRPCPort(t *testing.T) {
	config := NewGRPCConfig(WithGRPCPort(9000))
	if config.port != 9000 {
		t.Errorf("Expected port to be 9000, got %d", config.port)
	}
}

func TestWithGRPCHost(t *testing.T) {
	config := NewGRPCConfig(WithGRPCHost("example.com"))
	if config.host != "example.com" {
		t.Errorf("Expected host to be example.com, got %s", config.host)
	}
}

func TestMultipleGRPCOptions(t *testing.T) {
	config := NewGRPCConfig(
		WithGRPCPort(9090),
		WithGRPCHost("test.example.com"),
	)
	if config.port != 9090 {
		t.Errorf("Expected port to be 9090, got %d", config.port)
	}
	if config.host != "test.example.com" {
		t.Errorf("Expected host to be test.example.com, got %s", config.host)
	}
}

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

import "strconv"

type GRPCConfig struct {
	port     int
	host     string
	certFile string
	keyFile  string
}
type GRPCOption func(config *GRPCConfig)

func NewGRPCConfig(options ...func(config *GRPCConfig)) *GRPCConfig {
	config := &GRPCConfig{
		port: 8081,
		host: "localhost",
	}
	for _, opt := range options {
		opt(config)
	}

	return config
}

func WithGRPCPort(port int) GRPCOption {
	return func(config *GRPCConfig) {
		config.port = port
	}
}

func WithGRPCHost(host string) GRPCOption {
	return func(config *GRPCConfig) {
		config.host = host
	}
}

func (gc GRPCConfig) GRPCTarget() string {
	return gc.host + ":" + strconv.Itoa(gc.port)
}

func (gc GRPCConfig) HasTLS() bool {
	return gc.certFile != "" && gc.keyFile != ""
}

func WithTLSCredentials(certFile, keyFile string) GRPCOption {
	return func(config *GRPCConfig) {
		config.certFile = certFile
		config.keyFile = keyFile
	}
}

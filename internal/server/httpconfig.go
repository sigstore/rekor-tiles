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
	"strconv"
	"time"
)

type HTTPConfig struct {
	host               string
	timeout            time.Duration
	port               int
	metricsPort        int
	maxRequestBodySize int
	certFile           string
	keyFile            string
	grpcCertFile       string
	supportGCP         bool
}
type HTTPOption func(config *HTTPConfig)

func NewHTTPConfig(options ...func(config *HTTPConfig)) *HTTPConfig {
	config := &HTTPConfig{
		host:               "localhost",
		timeout:            defaultTimeout,
		port:               8080,
		metricsPort:        2112,
		maxRequestBodySize: defaultMaxSize,
	}
	for _, opt := range options {
		opt(config)
	}

	return config
}

func WithHTTPPort(port int) HTTPOption {
	return func(config *HTTPConfig) {
		config.port = port
	}
}

func WithHTTPHost(host string) HTTPOption {
	return func(config *HTTPConfig) {
		config.host = host
	}
}

func WithHTTPTimeout(timeout time.Duration) HTTPOption {
	return func(config *HTTPConfig) {
		config.timeout = timeout
	}
}

// WithHTTPMaxRequestBodySize specifies the maximum size of a requests's body.
func WithHTTPMaxRequestBodySize(size int) HTTPOption {
	return func(config *HTTPConfig) {
		config.maxRequestBodySize = size
	}
}

func WithHTTPMetricsPort(port int) HTTPOption {
	return func(config *HTTPConfig) {
		config.metricsPort = port
	}
}

func (hc HTTPConfig) HTTPTarget() string {
	return hc.host + ":" + strconv.Itoa(hc.port)
}

func (hc HTTPConfig) HTTPMetricsTarget() string { return hc.host + ":" + strconv.Itoa(hc.metricsPort) }

func (hc HTTPConfig) HasTLS() bool {
	return hc.certFile != "" && hc.keyFile != ""
}

func WithHTTPTLSCredentials(certFile, keyFile string) HTTPOption {
	return func(config *HTTPConfig) {
		config.certFile = certFile
		config.keyFile = keyFile
	}
}

func (hc HTTPConfig) HasGRPCTLS() bool {
	return hc.grpcCertFile != ""
}

func WithGRPCTLSCredentials(certFile string) HTTPOption {
	return func(config *HTTPConfig) {
		config.grpcCertFile = certFile
	}
}

func WithGCPSupport(supportGCP bool) HTTPOption {
	return func(config *HTTPConfig) {
		config.supportGCP = supportGCP
	}
}

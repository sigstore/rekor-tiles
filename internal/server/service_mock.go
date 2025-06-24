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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	pbsc "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/transparency-dev/tessera/api/layout"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// A testing mock that wraps server.Server to Start and defer Stop a server
type MockServer struct {
	gc           *GRPCConfig
	hc           *HTTPConfig
	wg           *sync.WaitGroup
	cleanupFiles []string
}

func (ms *MockServer) Start(t *testing.T) {
	ms.gc = NewGRPCConfig(
		WithGRPCHost("localhost"),
		WithGRPCPort(8081),
	)
	ms.hc = NewHTTPConfig(
		WithHTTPHost("localhost"),
		WithHTTPPort(8080),
	)

	s := &mockRekorServer{}
	shutdownFn := func(context.Context) error { return nil }

	// Start the server
	ms.wg = &sync.WaitGroup{}
	go func() {
		Serve(context.Background(), ms.hc, ms.gc, s, shutdownFn)
		ms.wg.Done()
	}()
	ms.wg.Add(1)

	// Healthcheck: Ping the /healthz endpoint until healthy
	for i := range 6 {
		if i == 5 {
			t.Fatal("mock server failed to startup")
		}
		resp, err := http.Get("http://localhost:8080/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("parsing response body: %v", err)
			}
			if strings.Contains(string(body), `{"status":"SERVING"}`) {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (ms *MockServer) StartTLS(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)
	ms.cleanupFiles = append(ms.cleanupFiles, certFile, keyFile)

	ms.gc = NewGRPCConfig(
		WithGRPCHost("localhost"),
		WithGRPCPort(8081),
		WithTLSCredentials(certFile, keyFile),
	)

	ms.hc = NewHTTPConfig(
		WithHTTPHost("localhost"),
		WithHTTPPort(8080),
		WithHTTPTLSCredentials(certFile, keyFile),
		WithGRPCTLSCredentials(certFile),
	)

	s := &mockRekorServer{}
	shutdownFn := func(context.Context) error { return nil }

	// Start the server
	ms.wg = &sync.WaitGroup{}
	go func() {
		Serve(context.Background(), ms.hc, ms.gc, s, shutdownFn)
		ms.wg.Done()
	}()
	ms.wg.Add(1)

	// Healthcheck: Ping the /healthz endpoint until it returns an expected error
	// because we're not initializing a connection over TLS.
	for i := range 6 {
		if i == 5 {
			t.Fatal("mock TLS server failed to startup")
		}
		resp, err := http.Get("http://localhost:8080/healthz")
		if err == nil && resp.StatusCode == http.StatusBadRequest {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("parsing response body: %v", err)
			}
			if strings.Contains(string(body), "Client sent an HTTP request to an HTTPS server") {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (ms *MockServer) Stop(t *testing.T) {
	// Simulate SIGTERM to trigger graceful shutdown
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("could not kill server")
	}
	ms.wg.Wait()

	for _, file := range ms.cleanupFiles {
		if err := os.Remove(file); err != nil {
			t.Logf("Failed to remove temp file %s: %v", file, err)
		}
	}
}

type mockRekorServer struct {
	pb.UnimplementedRekorServer
	grpc_health_v1.UnimplementedHealthServer
}

var testEntry = pbs.TransparencyLogEntry{
	LogIndex: 0,
	LogId: &pbsc.LogId{
		KeyId: []byte("abc"),
	},
	KindVersion: &pbs.KindVersion{
		Kind:    "placeholder",
		Version: "1.2.3",
	},
	IntegratedTime:   0,
	InclusionPromise: nil,
	InclusionProof: &pbs.InclusionProof{
		LogIndex: 0,
		RootHash: []byte("abc"),
		TreeSize: 0,
		Hashes:   [][]byte{[]byte("def"), []byte("ghi")},
		Checkpoint: &pbs.Checkpoint{
			Envelope: "placeholder",
		},
	},
	CanonicalizedBody: []byte("abcd"),
}

func (s *mockRekorServer) CreateEntry(_ context.Context, _ *pb.CreateEntryRequest) (*pbs.TransparencyLogEntry, error) {
	return &testEntry, nil
}

func (s *mockRekorServer) GetTile(_ context.Context, in *pb.TileRequest) (*httpbody.HttpBody, error) {
	// Verifies and parses level, index, and optional width for partial tile
	l, i, w, err := layout.ParseTileLevelIndexPartial(strconv.FormatUint(uint64(in.L), 10), in.N)
	if err != nil {
		return nil, err
	}
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-tile:%d,%d,%d", l, i, w)),
		Extensions:  nil,
	}, nil
}

func (s *mockRekorServer) GetEntryBundle(_ context.Context, in *pb.EntryBundleRequest) (*httpbody.HttpBody, error) {
	// Parses index, and optional width for partial tile
	i, w, err := layout.ParseTileIndexPartial(in.N)
	if err != nil {
		return nil, err
	}
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte(fmt.Sprintf("test-entries:%d,%d", i, w)),
		Extensions:  nil,
	}, nil
}

func (s *mockRekorServer) GetCheckpoint(_ context.Context, _ *emptypb.Empty) (*httpbody.HttpBody, error) {
	return &httpbody.HttpBody{
		ContentType: "application/octet-stream",
		Data:        []byte("test-checkpoint"),
		Extensions:  nil,
	}, nil
}

func (s mockRekorServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func generateSelfSignedCert(t testing.TB) (certFile, keyFile string) {
	t.Helper()

	tempDir := t.TempDir()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile = filepath.Join(tempDir, "cert.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("error closing cert.pem: %v", err)
	}

	keyFile = filepath.Join(tempDir, "key.pem")
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("error closing key.pem: %v", err)
	}

	return certFile, keyFile
}

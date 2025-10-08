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
	"crypto/x509"
	"os"
	"testing"

	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestServe_grpcSmoke(t *testing.T) {
	// To debug set slog to output to stdout
	// slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	server := MockServer{}

	server.Start(t)
	defer server.Stop(t)

	// check if we can hit grpc endpoints
	conn, err := grpc.NewClient(
		server.gc.GRPCTarget(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := pb.NewRekorClient(conn)
	defer conn.Close()
	defer server.Stop(t)
	testEndpoints(t, client)
}

func TestServe_grpcTLS(t *testing.T) {
	server := MockServer{}
	server.StartTLS(t)
	defer server.Stop(t)

	certPool := x509.NewCertPool()
	pemServerCert, err := os.ReadFile(server.gc.certFile)
	if err != nil {
		t.Fatalf("failed to read server certificate: %v", err)
	}
	if !certPool.AppendCertsFromPEM(pemServerCert) {
		t.Fatal("failed to add server certificate to pool")
	}

	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    certPool,
		ServerName: "localhost",
	})

	conn, err := grpc.NewClient(
		server.gc.GRPCTarget(),
		grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := pb.NewRekorClient(conn)
	testEndpoints(t, client)
}

func checkGRPCCreateEntry(t *testing.T, client pb.RekorClient) {
	if entry, err := client.CreateEntry(context.Background(), &pb.CreateEntryRequest{}); err != nil {
		t.Fatal(err)
	} else if !proto.Equal(entry, &testEntry) {
		t.Errorf("got entry %q, want %q", entry, &testEntry)
	}
}

func checkGRPC(t *testing.T, resp *httpbody.HttpBody, err error, expectedBody string) {
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data) != expectedBody {
		t.Errorf("got body %q, want %q", resp.Data, expectedBody)
	}
}

func testEndpoints(t *testing.T, client pb.RekorClient) {
	t.Helper()

	checkGRPCCreateEntry(t, client)

	t.Run("get checkpoint", func(t *testing.T) {
		body, err := client.GetCheckpoint(context.Background(), &emptypb.Empty{})
		checkGRPC(t, body, err, "test-checkpoint")
	})

	t.Run("get tile", func(t *testing.T) {
		body, err := client.GetTile(context.Background(), &pb.TileRequest{L: 1, N: "002"})
		checkGRPC(t, body, err, "test-tile:1,2,0")
	})

	t.Run("get tile with larger index", func(t *testing.T) {
		body, err := client.GetTile(context.Background(), &pb.TileRequest{L: 1, N: "x123/456"})
		checkGRPC(t, body, err, "test-tile:1,123456,0")
	})

	t.Run("get partial tile", func(t *testing.T) {
		body, err := client.GetTile(context.Background(), &pb.TileRequest{L: 1, N: "123.p/45"})
		checkGRPC(t, body, err, "test-tile:1,123,45")
	})

	t.Run("get tile with larger index and partial", func(t *testing.T) {
		body, err := client.GetTile(context.Background(), &pb.TileRequest{L: 1, N: "x123/456.p/7"})
		checkGRPC(t, body, err, "test-tile:1,123456,7")
	})

	t.Run("get entry bundle", func(t *testing.T) {
		body, err := client.GetEntryBundle(context.Background(), &pb.EntryBundleRequest{N: "001"})
		checkGRPC(t, body, err, "test-entries:1,0")
	})

	t.Run("get entry bundle with larger index", func(t *testing.T) {
		body, err := client.GetEntryBundle(context.Background(), &pb.EntryBundleRequest{N: "x123/456"})
		checkGRPC(t, body, err, "test-entries:123456,0")
	})

	t.Run("get partial entry bundle", func(t *testing.T) {
		body, err := client.GetEntryBundle(context.Background(), &pb.EntryBundleRequest{N: "123.p/45"})
		checkGRPC(t, body, err, "test-entries:123,45")
	})

	t.Run("get entry bundle with larger index and partial", func(t *testing.T) {
		body, err := client.GetEntryBundle(context.Background(), &pb.EntryBundleRequest{N: "x123/456.p/7"})
		checkGRPC(t, body, err, "test-entries:123456,7")
	})
}
func TestLoadTLSCredentials(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)
	t.Run("successful credentials loading", func(t *testing.T) {
		creds, err := loadTLSCredentials(certFile, keyFile)
		if err != nil {
			t.Fatalf("loadTLSCredentials failed: %v", err)
		}
		if creds == nil {
			t.Fatal("loadTLSCredentials returned nil credentials")
		}
	})

	t.Run("invalid certificate path", func(t *testing.T) {
		_, err := loadTLSCredentials("non-existent-cert.pem", keyFile)
		if err == nil {
			t.Fatal("expected error for invalid certificate path, got nil")
		}
	})

	t.Run("invalid key path", func(t *testing.T) {
		_, err := loadTLSCredentials(certFile, "non-existent-key.pem")
		if err == nil {
			t.Fatal("expected error for invalid key path, got nil")
		}
	})
	t.Run("invalid certificate content", func(t *testing.T) {
		invalidCertFile, err := os.CreateTemp("", "invalid-cert-*.pem")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(invalidCertFile.Name())

		if err := os.WriteFile(invalidCertFile.Name(), []byte("invalid certificate content"), 0644); err != nil {
			t.Fatalf("failed to write invalid cert: %v", err)
		}

		_, err = loadTLSCredentials(invalidCertFile.Name(), keyFile)
		if err == nil {
			t.Fatal("expected error for invalid certificate content, got nil")
		}
	})
}

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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestServe_smoke(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	gc := NewGRPCConfig()
	hc := NewHTTPConfig()
	s := &mockServer{}

	// Start the server
	var wg sync.WaitGroup
	go func() {
		Serve(context.Background(), hc, gc, s)
		wg.Done()
	}()
	wg.Add(1)

	// check if we can hit grpc endpoints
	conn, err := grpc.NewClient(
		gc.host+":"+strconv.Itoa(gc.port),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := pb.NewRekorClient(conn)
	defer conn.Close()
	checkGRPCCreateEntry(t, client)
	body, err := client.GetCheckpoint(context.Background(), &emptypb.Empty{})
	checkGRPC(t, body, err, "test-checkpoint")
	body, err = client.GetTile(context.Background(), &pb.TileRequest{L: 1, N: 2})
	checkGRPC(t, body, err, "test-tile:1,2")
	body, err = client.GetPartialTile(context.Background(), &pb.PartialTileRequest{L: 1, N: "2.p", W: 3})
	checkGRPC(t, body, err, "test-tile:1,2.p,3")
	body, err = client.GetEntryBundle(context.Background(), &pb.EntryBundleRequest{N: 1})
	checkGRPC(t, body, err, "test-entries:1")
	body, err = client.GetPartialEntryBundle(context.Background(), &pb.PartialEntryBundleRequest{N: "1.p", W: 2})
	checkGRPC(t, body, err, "test-entries:1.p,2")

	// Check if we can hit HTTP endpoints
	httpBaseURL := fmt.Sprintf("http://%s:%d", hc.host, hc.port)
	checkHTTPPost(t, httpBaseURL)
	checkHTTPGet(t, httpBaseURL+"/api/v2/checkpoint", "test-checkpoint")
	checkHTTPGet(t, httpBaseURL+"/api/v2/tile/1/2", "test-tile:1,2")
	checkHTTPGet(t, httpBaseURL+"/api/v2/tile/1/2.p/3", "test-tile:1,2.p,3")
	checkHTTPGet(t, httpBaseURL+"/api/v2/tile/entries/1", "test-entries:1")
	checkHTTPGet(t, httpBaseURL+"/api/v2/tile/entries/1.p/2", "test-entries:1.p,2")

	// Simulate SIGTERM to trigger graceful shutdown
	if err = syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Could not kill server")
	}

	wg.Wait()
}

func checkGRPCCreateEntry(t *testing.T, client pb.RekorClient) {
	if entry, err := client.CreateEntry(context.Background(), &pb.CreateEntryRequest{}); err != nil {
		t.Fatal(err)
	} else if !proto.Equal(entry, &testEntry) {
		t.Errorf("Got entry %q, want %q", entry, &testEntry)
	}
}

func checkGRPC(t *testing.T, resp *httpbody.HttpBody, err error, expectedBody string) {
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data) != expectedBody {
		t.Errorf("Got body %q, want %q", resp.Data, expectedBody)
	}
}

func checkHTTPPost(t *testing.T, httpBaseURL string) {
	resp, err := http.Post(httpBaseURL+"/api/v2/log/entries", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	entryJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var entry pbs.TransparencyLogEntry
	if err = protojson.Unmarshal(entryJSON, &entry); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&entry, &testEntry) {
		t.Errorf("\ngot  :%+v\nwant :%+v", &entry, &testEntry)
	}
}

func checkHTTPGet(t *testing.T, url, expectedBody string) {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf(url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("%s: got %d want %d", url, resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != expectedBody {
		t.Errorf("%s\ngot  :%q\nwant :%q", url, body, expectedBody)
	}
}

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
	"testing"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
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

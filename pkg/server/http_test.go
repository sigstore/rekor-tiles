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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestServe_httpSmoke(t *testing.T) {
	// To debug set slog to output to stdout
	// slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	server := MockServer{}
	server.Start(t)
	defer server.Stop(t)

	// Check if we can hit HTTP endpoints
	httpBaseURL := fmt.Sprintf("http://%s", server.hc.HTTPTarget())
	t.Run("check success", func(t *testing.T) {
		checkHTTPPost(t, httpBaseURL)
		checkHTTPGet(t, httpBaseURL+"/api/v2/checkpoint", "test-checkpoint")
		checkHTTPGet(t, httpBaseURL+"/api/v2/tile/1/2", "test-tile:1,2")
		checkHTTPGet(t, httpBaseURL+"/api/v2/tile/1/2.p/3", "test-tile:1,2.p,3")
		checkHTTPGet(t, httpBaseURL+"/api/v2/tile/entries/1", "test-entries:1")
		checkHTTPGet(t, httpBaseURL+"/api/v2/tile/entries/1.p/2", "test-entries:1.p,2")

		// healthcheck
		checkHTTPGet(t, httpBaseURL+"/healthz", `{"status":"SERVING"}`+"\n") // newline character is expected
	})
	t.Run("check failures", func(t *testing.T) {
		checkExtraJSONFieldsErrors(t, httpBaseURL)
	})
}

func checkHTTPPost(t *testing.T, httpBaseURL string) {
	resp, err := http.Post(httpBaseURL+"/api/v2/log/entries", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusOK)
		return
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

// we don't care if fields are missing yet (until we had "REQUIRED" validation), but we should fail for
// junk fields
func checkExtraJSONFieldsErrors(t *testing.T, httpBaseURL string) {
	resp, err := http.Post(httpBaseURL+"/api/v2/log/entries", "application/json", bytes.NewBufferString("{\"foo\":\"bar\"}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusOK)
		return
	}

}

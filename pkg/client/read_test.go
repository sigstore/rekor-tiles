//
// Copyright 2025 The Sigstore Authors.
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

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewReader(t *testing.T) {
	readURL := "http://localhost:7080"
	origin := "rekor-local"
	verifier, err := getVerifier(ed25519PrivKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		opts     []Option
		expected *readClient
	}{
		{
			name: "no options",
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
		{
			name: "with user agent",
			opts: []Option{
				WithUserAgent("test"),
			},
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
		{
			name: "with timeout",
			opts: []Option{
				WithTimeout(1 * time.Second),
			},
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
		{
			name: "with both",
			opts: []Option{
				WithUserAgent("test"),
				WithTimeout(1 * time.Second),
			},
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewReader(readURL, origin, verifier, test.opts...)
			assert.NoError(t, gotErr)
			assert.Equal(t, test.expected.baseURL, got.(*readClient).baseURL)
			assert.Equal(t, test.expected.origin, got.(*readClient).origin)
		})
	}
}

func TestReadCheckpoint(t *testing.T) {
	tests := []struct {
		name      string
		respBody  []byte
		respCode  int
		expectErr bool
	}{
		{
			name: "valid checkpoint",
			respBody: []byte(`rekor-local
2
vABc4Xj1G9UUySBRYDvTZpYtdDqbKN9XthAbY4Nqd/Y=

— rekor-local 2AtEIJwBlAY6KMMNAqcWRKgPZDhP6/bpBmefw4mD89JwL3KozxrLgz7MA8G5pM4UrGNoTOxxpW2bbdv/A5l22ymMLAU=
`),
			respCode:  http.StatusOK,
			expectErr: false,
		},
		{
			name:      "server error",
			respBody:  []byte("unexpected server error"),
			respCode:  http.StatusInternalServerError,
			expectErr: true,
		},
		{
			name: "invalid checkpoint",
			respBody: []byte(`wrong-origin
2
vABc4Xj1G9UUySBRYDvTZpYtdDqbKN9XthAbY4Nqd/Y=

— wrong-origin 2AtEIJwBlAY6KMMNAqcWRKgPZDhP6/bpBmefw4mD89JwL3KozxrLgz7MA8G5pM4UrGNoTOxxpW2bbdv/A5l22ymMLAU=
`),
			respCode:  http.StatusOK,
			expectErr: true,
		},
	}

	verifier, err := getVerifier(ed25519PrivKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(test.respCode)
					w.Write(test.respBody)
				}))
			defer server.Close()
			client, err := NewReader(server.URL, "rekor-local", verifier)
			if err != nil {
				t.Fatal(err)
			}
			gotCP, gotNote, gotErr := client.ReadCheckpoint(ctx)
			if test.expectErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			assert.NotNil(t, gotCP)
			assert.NotNil(t, gotNote)
		})
	}
}

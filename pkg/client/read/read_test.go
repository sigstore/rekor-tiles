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

package read

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sigstore/rekor-tiles/pkg/client"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

var ed25519PrivKey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc
-----END PRIVATE KEY-----
`

func TestNewReader(t *testing.T) {
	readURL := "http://localhost:7080"
	origin := "rekor-local"
	verifier, err := getVerifier(ed25519PrivKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		opts     []client.Option
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
			opts: []client.Option{
				client.WithUserAgent("test"),
			},
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
		{
			name: "with timeout",
			opts: []client.Option{
				client.WithTimeout(1 * time.Second),
			},
			expected: &readClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:7080", Path: "/"},
				origin:  "rekor-local",
			},
		},
		{
			name: "with both",
			opts: []client.Option{
				client.WithUserAgent("test"),
				client.WithTimeout(1 * time.Second),
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

func TestReadTile(t *testing.T) {
	tests := []struct {
		name      string
		tileIndex uint64
		serverErr bool
		expectErr bool
	}{
		{
			name:      "server success",
			tileIndex: 1,
			expectErr: false,
		},
		{
			name:      "server error",
			tileIndex: 1,
			serverErr: true,
			expectErr: true,
		},
		{
			name:      "out of range",
			tileIndex: 42,
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
					treeSize := uint64(10)
					if test.serverErr {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("unexpected server error"))
						return
					}
					if test.tileIndex > treeSize {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte("not found"))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("mozaics"))
				}))
			defer server.Close()
			client, err := NewReader(server.URL, "rekor-local", verifier)
			if err != nil {
				t.Fatal(err)
			}
			gotTile, gotErr := client.ReadTile(ctx, 0, test.tileIndex, 0)
			if test.expectErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			assert.NotNil(t, gotTile)
		})
	}
}

func TestReadEntryBundle(t *testing.T) {
	tests := []struct {
		name      string
		tileIndex uint64
		serverErr bool
		expectErr bool
	}{
		{
			name:      "server success",
			tileIndex: 1,
			expectErr: false,
		},
		{
			name:      "server error",
			tileIndex: 1,
			serverErr: true,
			expectErr: true,
		},
		{
			name:      "out of range",
			tileIndex: 42,
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
					treeSize := uint64(10)
					if test.serverErr {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("unexpected server error"))
						return
					}
					if test.tileIndex > treeSize {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte("not found"))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("mozaics"))
				}))
			defer server.Close()
			client, err := NewReader(server.URL, "rekor-local", verifier)
			if err != nil {
				t.Fatal(err)
			}
			gotTile, gotErr := client.ReadEntryBundle(ctx, test.tileIndex, 0)
			if test.expectErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			assert.NotNil(t, gotTile)
		})
	}
}

func getVerifier(privKey string) (signature.Verifier, error) {
	block, _ := pem.Decode([]byte(privKey))
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	verifier, err := signature.LoadDefaultSignerVerifier(priv.(ed25519.PrivateKey))
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

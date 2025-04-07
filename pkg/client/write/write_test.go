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

package write

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/pkg/client"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

var ed25519PrivKey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc
-----END PRIVATE KEY-----
`

func TestNewWriter(t *testing.T) {
	writeURL := "http://localhost:3003"
	origin := "rekor-local"
	verifier, err := getVerifier(ed25519PrivKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		opts     []client.Option
		expected *writeClient
	}{
		{
			name: "no options",
			expected: &writeClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:3003"},
				client:  &http.Client{Transport: http.DefaultTransport},
				origin:  "rekor-local",
			},
		},
		{
			name: "with user agent",
			opts: []client.Option{
				client.WithUserAgent("test"),
			},
			expected: &writeClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:3003"},
				client:  &http.Client{Transport: client.CreateRoundTripper(nil, "test")},
				origin:  "rekor-local",
			},
		},
		{
			name: "with timeout",
			opts: []client.Option{
				client.WithTimeout(1 * time.Second),
			},
			expected: &writeClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:3003"},
				client:  &http.Client{Transport: http.DefaultTransport, Timeout: 1 * time.Second},
				origin:  "rekor-local",
			},
		},
		{
			name: "with both",
			opts: []client.Option{
				client.WithUserAgent("test"),
				client.WithTimeout(1 * time.Second),
			},
			expected: &writeClient{
				baseURL: &url.URL{Scheme: "http", Host: "localhost:3003"},
				client: &http.Client{Transport: client.CreateRoundTripper(nil, "test"),
					Timeout: 1 * time.Second,
				},
				origin: "rekor-local",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewWriter(writeURL, origin, verifier, test.opts...)
			assert.NoError(t, gotErr)
			assert.Equal(t, test.expected.baseURL, got.(*writeClient).baseURL)
			assert.Equal(t, test.expected.client, got.(*writeClient).client)
			assert.Equal(t, test.expected.origin, got.(*writeClient).origin)
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name      string
		entry     any
		respBody  []byte
		respCode  int
		expectErr error
	}{
		{
			name: "valid hashedrekord",
			entry: &pb.HashedRekordRequestV0_0_2{
				Signature: &pb.Signature{
					Content: []byte("sign"),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: []byte("digest"),
			},
			respBody: marshalJSONOrDie(t, pbs.TransparencyLogEntry{
				LogIndex: 1,
				InclusionProof: &pbs.InclusionProof{
					LogIndex: 1,
					RootHash: b64DecodeOrDie(t, "NmVmNWM2YzY2NzcxNjI0YmZmMDI1ZDRmMGNkODRkYWVmYjI0MzIzMzk4MmU5MDA5M2Y0NDBkNDM5ODliY2ZiYgo="),
					TreeSize: 2,
					Hashes: [][]byte{
						b64DecodeOrDie(t, "d/XeBMMsM7fy/gMiRBFow5u6dOud2RFlKQy20qNSB8w="),
					},
					Checkpoint: &pbs.Checkpoint{
						Envelope: "rekor-local\n2\nbvXGxmdxYkv/Al1PDNhNrvskMjOYLpAJP0QNQ5ibz7s=\n\n— rekor-local 2AtEIKMQNqn1+JpFEwM4yv/nDtVtu0B6yGRkOLpbHP9tQMF493hYOgRKUhp9ZNylWSJebqOThUpdO03LzJn3/6K5HQc=\n",
					},
				},
				CanonicalizedBody: []byte(`{"data":{"algorithm":"SHA2_256","digest":"ZGlnZXN0"},"signature":"c2lnbg==","verifier":{"publicKey":{"rawBytes":"a2V5"}}}`),
			}),
			respCode:  http.StatusCreated,
			expectErr: nil,
		},
		{
			name: "valid dsse",
			entry: &pb.DSSERequestV0_0_2{
				Envelope: &dsse.Envelope{
					Payload:     []byte("some payload"),
					PayloadType: "",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("some signature"),
							Keyid: "abcd",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			respBody: marshalJSONOrDie(t, pbs.TransparencyLogEntry{
				LogIndex: 1,
				InclusionProof: &pbs.InclusionProof{
					RootHash: b64DecodeOrDie(t, "YmMwMDVjZTE3OGY1MWJkNTE0YzkyMDUxNjAzYmQzNjY5NjJkNzQzYTliMjhkZjU3YjYxMDFiNjM4MzZhNzdmNg=="),

					TreeSize: 2,
					Hashes: [][]byte{
						b64DecodeOrDie(t, "wWB4RFtzi4KkguQYjzcUge9No4fwgGMVdtQt6ls5B0I="),
					},
					Checkpoint: &pbs.Checkpoint{
						Envelope: "rekor-local\n2\nvABc4Xj1G9UUySBRYDvTZpYtdDqbKN9XthAbY4Nqd/Y=\n\n— rekor-local 2AtEIJwBlAY6KMMNAqcWRKgPZDhP6/bpBmefw4mD89JwL3KozxrLgz7MA8G5pM4UrGNoTOxxpW2bbdv/A5l22ymMLAU=\n",
					},
				},
				CanonicalizedBody: []byte(`{"envelope":"dsse","verifier":[{"publicKey":{"rawBytes":"a2V5"}}]}`),
			}),
			respCode:  http.StatusCreated,
			expectErr: nil,
		},
		{
			name:      "invalid entry type",
			entry:     "intoto entry",
			expectErr: fmt.Errorf("unsupported entry type: string"),
		},
		{
			name: "server error",
			entry: &pb.DSSERequestV0_0_2{
				Envelope: &dsse.Envelope{
					Payload:     []byte("some payload"),
					PayloadType: "",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("some signature"),
							Keyid: "abcd",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			respBody:  []byte("server died"),
			respCode:  http.StatusInternalServerError,
			expectErr: fmt.Errorf("unexpected response: 500 server died"),
		},
		{
			name: "unexpected response body from server",
			entry: &pb.DSSERequestV0_0_2{
				Envelope: &dsse.Envelope{
					Payload:     []byte("some payload"),
					PayloadType: "",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("some signature"),
							Keyid: "abcd",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			respBody:  []byte("i love ice cream"),
			respCode:  http.StatusCreated,
			expectErr: fmt.Errorf("unmarshaling response body: proto"),
		},
		{
			name: "invalid checkpoint",
			entry: &pb.DSSERequestV0_0_2{
				Envelope: &dsse.Envelope{
					Payload:     []byte("some payload"),
					PayloadType: "",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("some signature"),
							Keyid: "abcd",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
					},
				},
			},
			respBody: marshalJSONOrDie(t, pbs.TransparencyLogEntry{
				LogIndex: 1,
				InclusionProof: &pbs.InclusionProof{
					RootHash: b64DecodeOrDie(t, "YmMwMDVjZTE3OGY1MWJkNTE0YzkyMDUxNjAzYmQzNjY5NjJkNzQzYTliMjhkZjU3YjYxMDFiNjM4MzZhNzdmNg=="),

					TreeSize: 2,
					Hashes: [][]byte{
						b64DecodeOrDie(t, "wWB4RFtzi4KkguQYjzcUge9No4fwgGMVdtQt6ls5B0I="),
					},
					Checkpoint: &pbs.Checkpoint{
						Envelope: "wrong-origin\n2\nvABc4Xj1G9UUySBRYDvTZpYtdDqbKN9XthAbY4Nqd/Y=\n\n— rekor-local 2AtEIJwBlAY6KMMNAqcWRKgPZDhP6/bpBmefw4mD89JwL3KozxrLgz7MA8G5pM4UrGNoTOxxpW2bbdv/A5l22ymMLAU=\n",
					},
				},
				CanonicalizedBody: []byte(`{"envelope":"dsse","verifier":[{"publicKey":{"rawBytes":"a2V5"}}]}`),
			}),
			respCode:  http.StatusCreated,
			expectErr: fmt.Errorf("verifying transparency log entry: unverified checkpoint signature: failed to verify signatures on checkpoint: invalid signature for key"),
		},
		{
			name: "invalid inclusion proof",
			entry: &pb.DSSERequestV0_0_2{
				Envelope: &dsse.Envelope{
					Payload:     []byte("some payload"),
					PayloadType: "",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("some signature"),
							Keyid: "abcd",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("key"),
							},
						},
					},
				},
			},
			respBody: marshalJSONOrDie(t, pbs.TransparencyLogEntry{
				LogIndex: 1,
				InclusionProof: &pbs.InclusionProof{
					RootHash: b64DecodeOrDie(t, "YmMwMDVjZTE3OGY1MWJkNTE0YzkyMDUxNjAzYmQzNjY5NjJkNzQzYTliMjhkZjU3YjYxMDFiNjM4MzZhNzdmNg=="),

					TreeSize: 2,
					Hashes:   [][]byte{},
					Checkpoint: &pbs.Checkpoint{
						Envelope: "rekor-local\n2\nvABc4Xj1G9UUySBRYDvTZpYtdDqbKN9XthAbY4Nqd/Y=\n\n— rekor-local 2AtEIJwBlAY6KMMNAqcWRKgPZDhP6/bpBmefw4mD89JwL3KozxrLgz7MA8G5pM4UrGNoTOxxpW2bbdv/A5l22ymMLAU=\n",
					},
				},
				CanonicalizedBody: []byte(`{"envelope":"dsse","verifier":[{"publicKey":{"rawBytes":"a2V5"}}]}`),
			}),
			respCode:  http.StatusCreated,
			expectErr: fmt.Errorf("verifying transparency log entry: verifying inclusion: "),
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
					w.Write([]byte(test.respBody))
				}))
			defer server.Close()
			client, err := NewWriter(server.URL, "rekor-local", verifier)
			if err != nil {
				t.Fatal(err)
			}

			_, gotErr := client.Add(ctx, test.entry)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
			} else {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

func b64DecodeOrDie(t *testing.T, text string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func marshalJSONOrDie(t *testing.T, obj any) []byte {
	marshaledResp, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return marshaledResp
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

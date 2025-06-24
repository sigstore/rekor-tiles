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

package algorithmregistry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

func TestAlgorithmRegistry(t *testing.T) {
	tests := []struct {
		name             string
		algorithmOptions []string
		wantErr          bool
	}{
		{
			name:             "defaults",
			algorithmOptions: nil,
		},
		{
			name: "valid algorithms",
			algorithmOptions: []string{
				"ecdsa-sha2-384-nistp384",
				"ecdsa-sha2-512-nistp521",
				"ed25519",
				"rsa-sign-pkcs1-3072-sha256",
				"rsa-sign-pkcs1-4096-sha256",
			},
		},
		{
			name: "invalid algorithms",
			algorithmOptions: []string{
				"foo",
				"bar",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := AlgorithmRegistry(test.algorithmOptions)
			if test.wantErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			assert.NotNil(t, got)
		})
	}
}

func generateRSAKey(t *testing.T, bits int) *rsa.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return &priv.PublicKey
}

func generateECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return &priv.PublicKey
}

func generateEd25519Key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	return pub
}

func TestUnsupportedAlgorithm_Error(t *testing.T) {
	rsaKey2048 := generateRSAKey(t, 2048)
	rsaKey4096 := generateRSAKey(t, 4096)
	ecdsaKeyP256 := generateECDSAKey(t, elliptic.P256())
	ecdsaKeyP384 := generateECDSAKey(t, elliptic.P384())
	ed25519Key := generateEd25519Key(t)

	testCases := []struct {
		name string
		err  UnsupportedAlgorithm
		want string
	}{
		{
			name: "RSA 2048 with SHA256",
			err: UnsupportedAlgorithm{
				Pub: rsaKey2048,
				Alg: crypto.SHA256,
			},
			want: "unsupported entry algorithm for RSA key, size 2048, digest SHA-256",
		},
		{
			name: "RSA 4096 with SHA512",
			err: UnsupportedAlgorithm{
				Pub: rsaKey4096,
				Alg: crypto.SHA512,
			},
			want: "unsupported entry algorithm for RSA key, size 4096, digest SHA-512",
		},
		{
			name: "ECDSA P256 with SHA256",
			err: UnsupportedAlgorithm{
				Pub: ecdsaKeyP256,
				Alg: crypto.SHA256,
			},
			want: "unsupported entry algorithm for ECDSA key, curve P-256, digest SHA-256",
		},
		{
			name: "ECDSA P384 with SHA384",
			err: UnsupportedAlgorithm{
				Pub: ecdsaKeyP384,
				Alg: crypto.SHA384,
			},
			want: "unsupported entry algorithm for ECDSA key, curve P-384, digest SHA-384",
		},
		{
			name: "Ed25519 with SHA256",
			err: UnsupportedAlgorithm{
				Pub: ed25519Key,
				Alg: crypto.SHA256,
			},
			want: "unsupported entry algorithm for Ed25519 key, digest SHA-256",
		},
		{
			name: "nil public key",
			err: UnsupportedAlgorithm{
				Pub: nil,
				Alg: crypto.SHA256,
			},
			want: "unsupported key type %!s(<nil>), digest SHA-256",
		},
		{
			name: "unknown public key type",
			err: UnsupportedAlgorithm{
				Pub: int(1),
				Alg: crypto.SHA256,
			},
			want: "unsupported key type int, digest SHA-256",
		},
		{
			name: "zero hash value",
			err: UnsupportedAlgorithm{
				Pub: rsaKey2048,
				Alg: crypto.Hash(0),
			},
			want: "unsupported entry algorithm for RSA key, size 2048, digest unknown hash value 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if got != tc.want {
				t.Errorf("Error() mismatch:\ngot = %q\nwant= %q", got, tc.want)
			}
		})
	}
}

func TestUnsupportedAlgorithmForAllAllowedAlgs(t *testing.T) {
	for _, a := range AllowedClientSigningAlgorithms {
		details, err := signature.GetAlgorithmDetails(a)
		if err != nil {
			t.Fatal(err)
		}
		var pub crypto.PublicKey
		switch details.GetKeyType() {
		case signature.RSA:
			priv, err := rsa.GenerateKey(rand.Reader, 2048) // bit size doesn't matter for error
			if err != nil {
				t.Fatal(err)
			}
			pub = priv.Public()
		case signature.ECDSA:
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // curve doesn't matter for error
			if err != nil {
				t.Fatal(err)
			}
			pub = priv.Public()
		case signature.ED25519:
			pub, _, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
		}
		hash := details.GetHashType()
		uaErr := UnsupportedAlgorithm{Pub: pub, Alg: hash}
		if strings.Contains(uaErr.Error(), "unsupported key type") {
			t.Errorf("%v unexpected unsupported", a)
		}
	}
}

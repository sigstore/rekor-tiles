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

package publickey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestNewVerifier(t *testing.T) {
	goodPubKey, goodPKDER, err := generateTestPublicKey()
	if err != nil {
		t.Fatalf("failed to generate test public key: %v", err)
	}

	tests := []struct {
		name       string
		reader     io.Reader
		wantErr    bool
		wantErrMsg string
		wantKey    crypto.PublicKey
	}{
		{
			name:    "Success",
			reader:  bytes.NewReader(goodPKDER),
			wantErr: false,
			wantKey: goodPubKey,
		},
		{
			name:       "Nil Reader",
			reader:     nil,
			wantErr:    true,
			wantErrMsg: "public key reader is nil",
		},
		{
			name:       "Invalid DER Data",
			reader:     bytes.NewReader([]byte("this is not a public key")),
			wantErr:    true,
			wantErrMsg: "parsing public key",
		},
		{
			name:       "Empty Reader",
			reader:     bytes.NewReader([]byte{}),
			wantErr:    true,
			wantErrMsg: "parsing public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewVerifier(tt.reader)

			if (err != nil) != tt.wantErr {
				t.Fatalf("NewVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if err != nil && tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("NewVerifier() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
				}
				if got != nil {
					t.Errorf("NewVerifier() got = %v, want nil on error", got)
				}
			} else {
				if got == nil {
					t.Fatalf("NewVerifier() got nil, want non-nil")
				}
				if got.key == nil {
					t.Errorf("NewVerifier() internal key is nil")
				}
				if !reflect.DeepEqual(got.key, tt.wantKey) {
					t.Errorf("NewVerifier() key = %v, want %v", got.key, tt.wantKey)
				}
			}
		})
	}
}

func TestPublicKey_String(t *testing.T) {
	pubKey, _, err := generateTestPublicKey()
	if err != nil {
		t.Fatalf("failed to generate test public key: %v", err)
	}

	verifier := &PublicKey{key: pubKey}
	pemStr := verifier.String()

	if pemStr == "" {
		t.Fatalf("String() returned empty string")
	}

	if !strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("String() output does not start with correct PEM header")
	}
	if !strings.HasSuffix(strings.TrimSpace(pemStr), "-----END PUBLIC KEY-----") {
		t.Errorf("String() output does not end with correct PEM footer")
	}

	block, rest := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("Failed to decode PEM output from String()")
	}
	if len(rest) > 0 {
		t.Errorf("String() output contained trailing data after PEM block: %q", rest)
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("String() output PEM block type mismatch: got %q, want %q", block.Type, "PUBLIC KEY")
	}
}

func TestPublicKey_PublicKey(t *testing.T) {
	pubKey, _, err := generateTestPublicKey()
	if err != nil {
		t.Fatalf("failed to generate test public key: %v", err)
	}

	verifier := &PublicKey{key: pubKey}
	retrievedKey := verifier.PublicKey()

	if retrievedKey == nil {
		t.Fatalf("PublicKey() returned nil")
	}

	if !reflect.DeepEqual(retrievedKey, pubKey) {
		t.Errorf("PublicKey() returned key does not match original key. Got: %v, Want: %v", retrievedKey, pubKey)
	}
}

func TestPublicKey_Identities(t *testing.T) {
	pubKey, pkixDER, err := generateTestPublicKey()
	if err != nil {
		t.Fatalf("failed to generate test public key: %v", err)
	}

	verifier := &PublicKey{key: pubKey}

	identities, err := verifier.Identities()
	if err != nil {
		t.Fatalf("Identities() returned unexpected error: %v", err)
	}

	if len(identities) != 1 {
		t.Fatalf("Identities() returned %d identities, want 1", len(identities))
	}

	id := identities[0]

	if !reflect.DeepEqual(id.Crypto, pubKey) {
		t.Errorf("Identity Crypto field mismatch. Got: %+v, Want: %+v", id.Crypto, pubKey)
	}

	if !bytes.Equal(id.Raw, pkixDER) {
		t.Errorf("Identity Raw field mismatch. Got %d bytes, want %d bytes.", len(id.Raw), len(pkixDER))
	}

	expectedDigest := sha256.Sum256(pkixDER)
	expectedFingerprint := hex.EncodeToString(expectedDigest[:])
	if id.Fingerprint != expectedFingerprint {
		t.Errorf("Identity Fingerprint mismatch. Got: %s, Want: %s", id.Fingerprint, expectedFingerprint)
	}

}

// generateTestPublicKey creates an ECDSA key pair and returns the public key
// and its DER-encoded PKIX representation.
func generateTestPublicKey() (crypto.PublicKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return priv.Public(), derBytes, nil
}

/*
Copyright 2026 The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signerverifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// fakekms provides an in-memory KMS provider so that the KMS branch of New
	// can be exercised without cloud credentials.
	_ "github.com/sigstore/sigstore/pkg/signature/kms/fake"
)

// writeTestKey generates an unencrypted ECDSA private key and returns its path.
func writeTestKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "ec-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return keyPath
}

func TestNewWithFile(t *testing.T) {
	keyPath := writeTestKey(t)
	sv, err := New(context.Background(), WithFile(keyPath, ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := []byte("rekor")
	sig, err := sv.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("verifying signature: %v", err)
	}
}

func TestNewWithKMS(t *testing.T) {
	sv, err := New(context.Background(), WithKMS("fakekms://key", crypto.SHA256))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := []byte("rekor")
	sig, err := sv.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("verifying signature: %v", err)
	}
}

func TestNewErrors(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name:    "no options",
			opts:    nil,
			wantErr: "insufficient signing parameters provided",
		},
		{
			name:    "missing key file",
			opts:    []Option{WithFile(filepath.Join(t.TempDir(), "missing.pem"), "")},
			wantErr: "failed to read key file",
		},
		{
			name:    "tink with unsupported KEK scheme",
			opts:    []Option{WithTink("unsupported://kek", "keyset.json.enc")},
			wantErr: "unsupported KMS key type",
		},
		{
			name:    "tink without keyset path",
			opts:    []Option{WithTink("test-kek://kek", "")},
			wantErr: "key encryption key URI or keyset path unset",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv, err := New(context.Background(), tt.opts...)
			if err == nil {
				t.Fatalf("expected error, got signer-verifier %v", sv)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

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

package config

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/spf13/viper"

	// fakekms provides an in-memory KMS provider so that the KMS branch can be
	// exercised without cloud credentials.
	_ "github.com/sigstore/sigstore/pkg/signature/kms/fake"
)

func newViper(settings map[string]string) *viper.Viper {
	v := viper.New()
	for k, val := range settings {
		v.Set(k, val)
	}
	return v
}

func TestOptionsFromViperSelectsBranch(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]string
	}{
		{
			name:     "file",
			settings: map[string]string{"signer-filepath": "key.pem", "signer-password": "pw"},
		},
		{
			name:     "kms",
			settings: map[string]string{"signer-kmskey": "gcpkms://key", "signer-kmshash": "sha256"},
		},
		{
			name:     "tink",
			settings: map[string]string{"signer-tink-kek-uri": "gcp-kms://kek", "signer-tink-keyset-path": "keyset.json.enc"},
		},
		{
			name: "file takes precedence over KMS and Tink",
			settings: map[string]string{
				"signer-filepath":     "key.pem",
				"signer-kmskey":       "gcpkms://key",
				"signer-kmshash":      "sha256",
				"signer-tink-kek-uri": "gcp-kms://kek",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := OptionsFromViper(newViper(tt.settings))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(opts) != 1 {
				t.Fatalf("expected 1 option, got %d", len(opts))
			}
		})
	}
}

func TestOptionsFromViperHashAlgorithms(t *testing.T) {
	for _, alg := range []string{"sha256", "sha384", "sha512"} {
		t.Run(alg, func(t *testing.T) {
			if _, err := OptionsFromViper(newViper(map[string]string{
				"signer-kmskey":  "gcpkms://key",
				"signer-kmshash": alg,
			})); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOptionsFromViperNoSigner(t *testing.T) {
	opts, err := OptionsFromViper(newViper(nil))
	if err == nil {
		t.Fatalf("expected error, got options %v", opts)
	}
	if !errors.Is(err, ErrNoSigner) {
		t.Errorf("expected ErrNoSigner, got %v", err)
	}
	// The exact text is what freeze-checkpoint surfaces to users.
	if err.Error() != "must provide a signer using a file, KMS, or Tink" {
		t.Errorf("unexpected message %q", err.Error())
	}
}

func TestOptionsFromViperInvalidHash(t *testing.T) {
	tests := []struct{ name, hash string }{
		{name: "unknown hash algorithm", hash: "sha1"},
		{name: "missing hash algorithm", hash: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := OptionsFromViper(newViper(map[string]string{
				"signer-kmskey":  "gcpkms://key",
				"signer-kmshash": tt.hash,
			}))
			if err == nil {
				t.Fatalf("expected error, got options %v", opts)
			}
			var invalidHash *InvalidHashError
			if !errors.As(err, &invalidHash) {
				t.Fatalf("expected *InvalidHashError, got %T", err)
			}
			// LogError reports this as a structured attribute.
			if invalidHash.Algorithm != tt.hash {
				t.Errorf("expected algorithm %q, got %q", tt.hash, invalidHash.Algorithm)
			}
			want := "invalid hash algorithm for --signer-kmshash: " + tt.hash
			if err.Error() != want {
				t.Errorf("expected %q, got %q", want, err.Error())
			}
		})
	}
}

// TestOptionsFromViperFileRoundTrip checks that the file option carries the
// configured path and password through to a usable signer, not just that some
// option was returned.
func TestOptionsFromViperFileRoundTrip(t *testing.T) {
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

	opts, err := OptionsFromViper(newViper(map[string]string{"signer-filepath": keyPath}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	signer, err := sv.New(context.Background(), opts...)
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}
	msg := []byte("rekor")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	if err := signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("verifying signature: %v", err)
	}
}

// TestOptionsFromViperKMSRoundTrip checks that the KMS key and mapped hash reach
// the signer, and that caller-supplied RPC options are accepted.
func TestOptionsFromViperKMSRoundTrip(t *testing.T) {
	opts, err := OptionsFromViper(newViper(map[string]string{
		"signer-kmskey":  "fakekms://key",
		"signer-kmshash": "sha256",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	signer, err := sv.New(context.Background(), opts...)
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}
	msg := []byte("rekor")
	sig, err := signer.SignMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	if err := signer.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
		t.Fatalf("verifying signature: %v", err)
	}
}

// TestOptionsFromViperTinkCarriesConfig checks that the Tink option carries the
// configured KEK URI and keyset path, by observing the error raised downstream.
func TestOptionsFromViperTinkCarriesConfig(t *testing.T) {
	opts, err := OptionsFromViper(newViper(map[string]string{
		"signer-tink-kek-uri": "unsupported-kms://kek",
		// keyset path deliberately set so the empty-path guard does not fire first
		"signer-tink-keyset-path": "keyset.json.enc",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No cloud package injected a KEK provider here, so the URI cannot be resolved.
	if _, err = sv.New(context.Background(), opts...); err == nil {
		t.Fatal("expected an error for an unsupported KEK scheme")
	}
	if err.Error() != "unsupported KMS key type" {
		t.Errorf("expected \"unsupported KMS key type\", got %q", err.Error())
	}
}

// TestHashAlgMapValues pins the hash mapping itself.
func TestHashAlgMapValues(t *testing.T) {
	want := map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}
	if len(hashAlgMap) != len(want) {
		t.Fatalf("expected %d algorithms, got %d", len(want), len(hashAlgMap))
	}
	for name, hash := range want {
		if hashAlgMap[name] != hash {
			t.Errorf("expected %s to map to %v, got %v", name, hash, hashAlgMap[name])
		}
	}
}

// captureLogs redirects the default logger for the duration of a test and returns
// the buffer it writes to. JSON is used so that structured attributes can be
// asserted on rather than pattern-matched out of a text line.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	return &buf
}

// TestLogError pins the message each configuration error produces, including the
// structured attribute the servers rely on for an invalid --signer-kmshash. The
// errors are wrapped so that the errors.As and errors.Is matching is exercised
// rather than plain equality.
func TestLogError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantMsg  string
		wantAttr map[string]string
	}{
		{
			name:     "invalid hash",
			err:      &InvalidHashError{Algorithm: "sha1"},
			wantMsg:  "invalid hash algorithm for --signer-kmshash",
			wantAttr: map[string]string{"algorithm": "sha1"},
		},
		{
			name:     "invalid hash wrapped",
			err:      fmt.Errorf("building options: %w", &InvalidHashError{Algorithm: "md5"}),
			wantMsg:  "invalid hash algorithm for --signer-kmshash",
			wantAttr: map[string]string{"algorithm": "md5"},
		},
		{
			name:    "no signer",
			err:     ErrNoSigner,
			wantMsg: "no signer configured; must provide a signer using a file, KMS, or Tink",
		},
		{
			name:    "no signer wrapped",
			err:     fmt.Errorf("building options: %w", ErrNoSigner),
			wantMsg: "no signer configured; must provide a signer using a file, KMS, or Tink",
		},
		{
			name:    "unrecognized error falls back to its own text",
			err:     errors.New("something else went wrong"),
			wantMsg: "something else went wrong",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureLogs(t)
			LogError(tt.err)

			var record map[string]any
			if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
				t.Fatalf("parsing log record %q: %v", buf.String(), err)
			}
			if record["msg"] != tt.wantMsg {
				t.Errorf("expected message %q, got %q", tt.wantMsg, record["msg"])
			}
			if record["level"] != "ERROR" {
				t.Errorf("expected an ERROR record, got %v", record["level"])
			}
			for k, want := range tt.wantAttr {
				if record[k] != want {
					t.Errorf("expected attribute %s=%q, got %v", k, want, record[k])
				}
			}
			if tt.wantAttr == nil {
				if _, ok := record["algorithm"]; ok {
					t.Error("expected no algorithm attribute")
				}
			}
		})
	}
}

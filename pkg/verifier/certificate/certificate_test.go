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

package certificate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewVerifier(t *testing.T) {
	validCert, validDER, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tests := []struct {
		name        string
		reader      io.Reader
		wantErr     bool
		wantErrMsg  string
		wantCertRaw []byte
	}{
		{
			name:        "Success",
			reader:      bytes.NewReader(validDER),
			wantErr:     false,
			wantCertRaw: validDER,
		},
		{
			name:       "Invalid DER Data",
			reader:     bytes.NewReader([]byte("this is not a certificate")),
			wantErr:    true,
			wantErrMsg: "parsing certificate",
		},
		{
			name:       "Empty Reader",
			reader:     bytes.NewReader([]byte{}),
			wantErr:    true,
			wantErrMsg: "parsing certificate",
		},
		{
			name:       "Nil Reader",
			reader:     nil,
			wantErr:    true,
			wantErrMsg: "certificate reader is nil",
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
				if got.cert == nil {
					t.Fatalf("NewVerifier() internal cert is nil")
				}
				if !bytes.Equal(got.cert.Raw, tt.wantCertRaw) {
					t.Errorf("NewVerifier() certificate raw bytes do not match input")
				}
				if !reflect.DeepEqual(got.cert, validCert) {
					t.Errorf("NewVerifier() internal cert mismatch. got = %+v, want = %+v", got.cert, validCert)
				}
			}
		})
	}
}

func TestCertificate_String(t *testing.T) {
	cert, der, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	verifier := &Certificate{cert: cert}
	pemStr := verifier.String()

	if pemStr == "" {
		t.Fatalf("String() returned empty string")
	}

	if !strings.HasPrefix(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("String() output does not start with PEM header")
	}
	if !strings.HasSuffix(strings.TrimSpace(pemStr), "-----END CERTIFICATE-----") {
		t.Errorf("String() output does not end with PEM footer")
	}

	block, rest := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("failed to decode PEM output from String()")
	}
	if len(rest) > 0 {
		t.Errorf("String() output contained trailing data after PEM block: %q", rest)
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("String() output PEM block type mismatch: got %q, want %q", block.Type, "CERTIFICATE")
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Errorf("String() PEM decoded bytes do not match original DER bytes")
	}
}

func TestCertificate_PublicKey(t *testing.T) {
	cert, _, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	verifier := &Certificate{cert: cert}
	pubKey := verifier.PublicKey()

	if pubKey == nil {
		t.Fatalf("PublicKey() returned nil")
	}

	if !reflect.DeepEqual(pubKey, cert.PublicKey) {
		t.Errorf("PublicKey() returned key does not match certificate's public key. Got: %v, Want: %v", pubKey, cert.PublicKey)
	}
}

func TestCertificate_Identities(t *testing.T) {
	cert, der, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}

	verifier := &Certificate{cert: cert}

	identities, err := verifier.Identities()
	if err != nil {
		t.Fatalf("Identities() returned unexpected error: %v", err)
	}

	if len(identities) != 1 {
		t.Fatalf("Identities() returned %d identities, want 1", len(identities))
	}

	id := identities[0]
	if !reflect.DeepEqual(id.Crypto, cert) {
		t.Errorf("Identity Crypto field mismatch. Got: %+v, Want: %+v", id.Crypto, cert)
	}
	if !bytes.Equal(id.Raw, der) {
		t.Errorf("Identity Raw field mismatch.")
	}
	expectedDigest := sha256.Sum256(der)
	expectedFingerprint := hex.EncodeToString(expectedDigest[:])
	if id.Fingerprint != expectedFingerprint {
		t.Errorf("Identity Fingerprint mismatch. Got: %s, Want: %s", id.Fingerprint, expectedFingerprint)
	}
}

// generateTestCertificate creates a self-signed certificate for testing.
// Returns the parsed certificate, its DER encoding, and the private key.
func generateTestCertificate() (*x509.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test org"},
			CommonName:   "Test Name",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign, we don't validate that the certificate is a leaf
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, derBytes, nil
}

// Copyright 2026 The Sigstore Authors.
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

package mldsa

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
)

func TestMLDSASignerVerifier(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}

	sv, err := LoadMLDSASignerVerifier(priv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	// Verify that a bad signature fails
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[0] ^= 0xFF
	err = sv.VerifySignature(bytes.NewReader(badSig), bytes.NewReader(message))
	if err == nil {
		t.Fatalf("expected error verifying bad signature, got nil")
	}

	// Verify that a bad message fails
	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("bad message")))
	if err == nil {
		t.Fatalf("expected error verifying bad message, got nil")
	}

	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}
}

func TestMLDSAVerifier(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("unexpected error creating key: %v", err)
	}

	sv, err := LoadMLDSASignerVerifier(priv)
	if err != nil {
		t.Fatalf("unexpected error creating signer/verifier: %v", err)
	}

	pubKey := priv.Public().(*mldsa.PublicKey)

	v, err := LoadMLDSAVerifier(pubKey)
	if err != nil {
		t.Fatalf("unexpected error creating verifier: %v", err)
	}

	message := []byte("sign me")
	sig, err := sv.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error signing message: %v", err)
	}

	err = v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
	if err != nil {
		t.Fatalf("unexpected error verifying signature: %v", err)
	}

	pub, err := v.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error from PublicKey(): %v", err)
	}
	if pub == nil {
		t.Fatalf("expected public key, got nil")
	}
}

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
	"crypto"
	"errors"
	"fmt"
	"io"

	"filippo.io/mldsa"
	"github.com/sigstore/sigstore/pkg/signature"
)

// MLDSASigner is a signature.Signer that uses the ML-DSA post-quantum signature scheme.
//
// WARNING: This is experimental and may change.
//
//nolint:revive
type MLDSASigner struct {
	priv *mldsa.PrivateKey
}

// LoadMLDSASigner calculates signatures using the specified private key.
func LoadMLDSASigner(priv *mldsa.PrivateKey) (*MLDSASigner, error) {
	if priv == nil {
		return nil, errors.New("invalid ML-DSA private key specified")
	}

	return &MLDSASigner{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message. Passing the WithDigest option is not
// supported as ML-DSA handles its own internal message processing.
//
// All options are ignored.
func (m MLDSASigner) SignMessage(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}

	return m.priv.Sign(nil, messageBytes, nil)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (m MLDSASigner) Public() crypto.PublicKey {
	if m.priv == nil {
		return nil
	}

	return m.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.Public(), nil
}

// MLDSAVerifier is a signature.Verifier that uses the ML-DSA post-quantum signature system.
//
// WARNING: This is experimental and may change.
//
//nolint:revive
type MLDSAVerifier struct {
	publicKey *mldsa.PublicKey
}

// LoadMLDSAVerifier returns a Verifier that verifies signatures using the specified ML-DSA public key.
func LoadMLDSAVerifier(pub *mldsa.PublicKey) (*MLDSAVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ML-DSA public key specified")
	}

	return &MLDSAVerifier{
		publicKey: pub,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m *MLDSAVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}

// VerifySignature verifies the signature for the given message.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// All options are ignored if specified.
func (m *MLDSAVerifier) VerifySignature(sig, message io.Reader, _ ...signature.VerifyOption) error {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}

	if sig == nil {
		return errors.New("nil signature passed to VerifySignature")
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	return mldsa.Verify(m.publicKey, messageBytes, sigBytes, nil)
}

// MLDSASignerVerifier is a signature.SignerVerifier that uses the ML-DSA post-quantum signature system
//
//nolint:revive
type MLDSASignerVerifier struct {
	*MLDSASigner
	*MLDSAVerifier
}

// LoadMLDSASignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of MLDSASigner and MLDSAVerifier.
func LoadMLDSASignerVerifier(priv *mldsa.PrivateKey) (*MLDSASignerVerifier, error) {
	signer, err := LoadMLDSASigner(priv)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	pub, ok := priv.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("given key is not *mldsa.PublicKey")
	}
	verifier, err := LoadMLDSAVerifier(pub)
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &MLDSASignerVerifier{
		MLDSASigner:   signer,
		MLDSAVerifier: verifier,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (m MLDSASignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.publicKey, nil
}

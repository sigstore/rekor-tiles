// Copyright 2026 The Sigstore Authors
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

package identity_v1

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	SpecDomainSeparator = "c2sp.org/identity-transparency/v1"
	LeafVersion         = byte(0x01)
	ContextKeyName      = "context"
)

func validate(req *pb.IdentityRequestV001) error {
	if req == nil {
		return errors.New("request is nil")
	}

	switch cred := req.Credential.(type) {
	case *pb.IdentityRequestV001_PublicKey:
		if len(cred.PublicKey.GetPublicKey()) == 0 {
			return errors.New("public key is empty")
		}
		if len(cred.PublicKey.GetSignature()) == 0 {
			return errors.New("signature is empty")
		}
		if len(cred.PublicKey.GetContext()) > 0 && len(cred.PublicKey.GetContext()) != sha256.Size {
			return errors.New("invalid context value hash size, must be 32 bytes")
		}
	default:
		return errors.New("unsupported or missing credential type")
	}

	if len(req.GetMessage()) != sha256.Size {
		return errors.New("invalid message hash size, must be 32 bytes")
	}

	return nil
}

func appendMessageAndContext(buf []byte, req *pb.IdentityRequestV001) []byte {
	msgHash := sha256.Sum256(req.GetMessage())
	buf = append(buf, msgHash[:]...)

	if contextBytes := req.GetPublicKey().GetContext(); len(contextBytes) > 0 {
		k1 := sha256.Sum256([]byte(ContextKeyName))
		kDoubleHash := sha256.Sum256(k1[:])
		vDoubleHash := sha256.Sum256(contextBytes)
		buf = append(buf, kDoubleHash[:]...)
		buf = append(buf, vDoubleHash[:]...)
	}

	return buf
}

func computeSignaturePayload(req *pb.IdentityRequestV001) []byte {
	payload := append([]byte(SpecDomainSeparator), 0x00)
	return appendMessageAndContext(payload, req)
}

func computeLeaf(req *pb.IdentityRequestV001, rootPubKeyHash []byte) []byte {
	leaf := append([]byte{LeafVersion}, rootPubKeyHash...)
	leaf = appendMessageAndContext(leaf, req)

	// Note: Rekor does not currently store the signature as a receipt
	// to prove a valid credential was provided. In a future revision,
	// Rekor will persist the signature in out-of-tree storage.
	sigHash := sha256.Sum256(req.GetPublicKey().GetSignature())
	return append(leaf, sigHash[:]...)
}

// ToLogEntry validates an identity request, verifies its signature, and returns the unhashed leaf format.
func ToLogEntry(req *pb.IdentityRequestV001, algorithmRegistry *signature.AlgorithmRegistryConfig) ([]byte, error) {
	if err := validate(req); err != nil {
		return nil, err
	}

	var pubKey, sig []byte
	switch cred := req.Credential.(type) {
	case *pb.IdentityRequestV001_PublicKey:
		pubKey = cred.PublicKey.GetPublicKey()
		sig = cred.PublicKey.GetSignature()
	default:
		return nil, errors.New("unsupported credential type")
	}

	pub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	if algorithmRegistry != nil {
		valid, err := algorithmregistry.CheckAlgorithm(pub, crypto.Hash(0), algorithmRegistry)
		if err != nil {
			return nil, fmt.Errorf("checking entry algorithm: %w", err)
		}
		if !valid {
			return nil, &algorithmregistry.UnsupportedAlgorithm{Pub: pub, Alg: crypto.Hash(0)}
		}
	}
	edKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an Ed25519 key")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature length, must be 64 bytes for Ed25519")
	}

	payload := computeSignaturePayload(req)

	if !ed25519.Verify(edKey, payload, sig) {
		return nil, errors.New("invalid signature")
	}

	// Canonicalize the public key for hashing
	canonicalPubKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	rootOfTrust := append([]byte("Ed25519"), canonicalPubKey...)
	rootPubKeyHash := sha256.Sum256(rootOfTrust)
	return computeLeaf(req, rootPubKeyHash[:]), nil
}

// ToEntryHash reconstructs the identity log entry from bundle-signed
// inputs and returns its entry hash.
func ToEntryHash(publicKey []byte, signature []byte, message []byte, context []byte) ([]byte, error) {
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: publicKey,
				Signature: signature,
				Context:   context,
			},
		},
		Message: message,
	}
	leafBytes, err := ToLogEntry(req, nil)
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(leafBytes), nil
}

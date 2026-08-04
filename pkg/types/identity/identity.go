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

package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"

	"github.com/sigstore/fulcio/pkg/config"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	SpecDomainSeparatorV1 = "c2sp.org/identity-transparency/v1"
	LeafVersionV1         = byte(0x01)
	ContextKeyName        = "context"
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
		if len(cred.PublicKey.GetSignature()) != ed25519.SignatureSize {
			return errors.New("invalid signature length, must be 64 bytes for Ed25519")
		}
		if len(cred.PublicKey.GetContext()) > 0 && len(cred.PublicKey.GetContext()) != sha256.Size {
			return errors.New("invalid context value hash size, must be 32 bytes")
		}
	case *pb.IdentityRequestV001_Oidc:
		if len(cred.Oidc.GetToken()) == 0 {
			return errors.New("oidc token is empty")
		}
	default:
		return errors.New("unsupported or missing credential type")
	}

	if len(req.GetMessage()) != sha256.Size {
		return errors.New("invalid message hash size, must be 32 bytes")
	}

	return nil
}

func computeSignaturePayload(req *pb.IdentityRequestV001) []byte {
	payload := []byte(SpecDomainSeparatorV1)
	payload = append(payload, 0x00)

	msgHash := sha256.Sum256(req.GetMessage())
	payload = append(payload, msgHash[:]...)

	var contextBytes []byte
	if cred, ok := req.Credential.(*pb.IdentityRequestV001_PublicKey); ok {
		contextBytes = cred.PublicKey.GetContext()
	}

	if len(contextBytes) > 0 {
		k1 := sha256.Sum256([]byte(ContextKeyName))
		kDoubleHash := sha256.Sum256(k1[:])
		vDoubleHash := sha256.Sum256(contextBytes)
		payload = append(payload, kDoubleHash[:]...)
		payload = append(payload, vDoubleHash[:]...)
	}

	return payload
}

func computeLeafHash(req *pb.IdentityRequestV001, rootPubKeyHash []byte, oidcClaims map[string]string) []byte {
	leaf := []byte{LeafVersionV1}

	leaf = append(leaf, rootPubKeyHash...)

	msgHash := sha256.Sum256(req.GetMessage())
	leaf = append(leaf, msgHash[:]...)

	if cred, ok := req.Credential.(*pb.IdentityRequestV001_PublicKey); ok {
		contextBytes := cred.PublicKey.GetContext()
		if len(contextBytes) > 0 {
			k1 := sha256.Sum256([]byte(ContextKeyName))
			kDoubleHash := sha256.Sum256(k1[:])
			vDoubleHash := sha256.Sum256(contextBytes)
			leaf = append(leaf, kDoubleHash[:]...)
			leaf = append(leaf, vDoubleHash[:]...)
		}
		sig := cred.PublicKey.GetSignature()
		// Note: Rekor does not currently store the signature as a receipt
		// to prove a valid credential was provided. In a future revision,
		// Rekor will persist the signature in out-of-tree storage.
		sigHash := sha256.Sum256(sig)
		leaf = append(leaf, sigHash[:]...)
	} else if _, ok := req.Credential.(*pb.IdentityRequestV001_Oidc); ok {
		if len(oidcClaims) > 0 {
			var keys []string
			for k := range oidcClaims {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := oidcClaims[k]
				keyHash := sha256.Sum256([]byte(k))
				valHash := sha256.Sum256([]byte(v))
				kDoubleHash := sha256.Sum256(keyHash[:])
				vDoubleHash := sha256.Sum256(valHash[:])
				leaf = append(leaf, kDoubleHash[:]...)
				leaf = append(leaf, vDoubleHash[:]...)
			}
		}
		leaf = append(leaf, make([]byte, 32)...)
	}

	return leaf
}

// ToLogEntry reconstructs the leaf bytes from bundle-signed inputs.
// It validates the signature and returns the unhashed leaf format, as well as an
// optional map of raw context key-value pairs (e.g. for OIDC claims).
func ToLogEntry(ctx context.Context, req *pb.IdentityRequestV001, cfg *config.FulcioConfig) ([]byte, map[string]string, error) {
	if err := validate(req); err != nil {
		return nil, nil, err
	}

	switch cred := req.Credential.(type) {
	case *pb.IdentityRequestV001_PublicKey:
		pubKey := cred.PublicKey.GetPublicKey()
		sig := cred.PublicKey.GetSignature()

		pub, err := x509.ParsePKIXPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		edKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("public key is not an Ed25519 key")
		}

		payload := computeSignaturePayload(req)

		if !ed25519.Verify(edKey, payload, sig) {
			return nil, nil, errors.New("invalid signature")
		}

		rootOfTrust := append([]byte("Ed25519"), pubKey...)
		rootPubKeyHash := sha256.Sum256(rootOfTrust)
		return computeLeafHash(req, rootPubKeyHash[:], nil), nil, nil

	case *pb.IdentityRequestV001_Oidc:
		issuer, claims, err := extractOIDCClaims(ctx, cred.Oidc.GetToken(), cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract OIDC claims: %w", err)
		}

		rootPubKeyHash := sha256.Sum256([]byte(issuer))
		return computeLeafHash(req, rootPubKeyHash[:], claims), claims, nil

	default:
		return nil, nil, errors.New("unsupported credential type")
	}
}

// ToEntryHash reconstructs the identity log entry from bundle-signed
// inputs and returns its entry hash.
func ToEntryHash(publicKey []byte, signature []byte, message []byte, contextBytes []byte) ([]byte, error) {
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: publicKey,
				Signature: signature,
				Context:   contextBytes,
			},
		},
		Message: message,
	}
	leafBytes, _, err := ToLogEntry(context.Background(), req, nil)
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(leafBytes), nil
}

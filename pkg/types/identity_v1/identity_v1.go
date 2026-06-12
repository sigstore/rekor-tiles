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
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sigstore/fulcio/pkg/identity"
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

func computeLeaf(req *pb.IdentityRequestV001, rootOfTrustHash []byte, oidcClaims map[string]string) []byte {
	// Prefix leaf with the 1-byte leaf version (0x01) and 32-byte root-of-trust hash
	// (SHA-256 of the OIDC issuer URL for OIDC credentials, and SHA-256 of the public key for public key credentials).
	leaf := append([]byte{LeafVersion}, rootOfTrustHash...)

	if _, ok := req.Credential.(*pb.IdentityRequestV001_PublicKey); ok {
		leaf = appendMessageAndContext(leaf, req)
		// Note: Rekor does not currently store the signature as a receipt
		// to prove a valid credential was provided. In a future revision,
		// Rekor will persist the signature in out-of-tree storage.
		sigHash := sha256.Sum256(req.GetPublicKey().GetSignature())
		leaf = append(leaf, sigHash[:]...)
	} else if _, ok := req.Credential.(*pb.IdentityRequestV001_Oidc); ok {
		// Append SHA-256 of the 32-byte message digest (i.e. double-hashed artifact data).
		msgHash := sha256.Sum256(req.GetMessage())
		leaf = append(leaf, msgHash[:]...)
		if len(oidcClaims) > 0 {
			type hashedPair struct {
				kDoubleHash [sha256.Size]byte
				vDoubleHash [sha256.Size]byte
			}
			// Double-hash each extracted OIDC claim key and value: SHA256(SHA256(k)) and SHA256(SHA256(v)).
			pairs := make([]hashedPair, 0, len(oidcClaims))
			for k, v := range oidcClaims {
				keyHash := sha256.Sum256([]byte(k))
				valHash := sha256.Sum256([]byte(v))
				pairs = append(pairs, hashedPair{
					kDoubleHash: sha256.Sum256(keyHash[:]),
					vDoubleHash: sha256.Sum256(valHash[:]),
				})
			}
			// Sort context key-value pairs lexicographically by the double-hashed key for determinism.
			slices.SortFunc(pairs, func(a, b hashedPair) int {
				return bytes.Compare(a.kDoubleHash[:], b.kDoubleHash[:])
			})
			for _, p := range pairs {
				leaf = append(leaf, p.kDoubleHash[:]...)
				leaf = append(leaf, p.vDoubleHash[:]...)
			}
		}
		// Append 32 zero bytes to signify no receipt of the credential.
		// In a future revision, we may want to include a zero-knowledge proof over
		// a valid identity token instead.
		leaf = append(leaf, make([]byte, 32)...)
	}

	return leaf
}

// ToLogEntry validates an identity request, verifies its public key signature
// or OIDC credential, and returns the unhashed leaf format along with the
// formatted extraData bytes for the transparency log proof.
func ToLogEntry(ctx context.Context, req *pb.IdentityRequestV001, algorithmRegistry *signature.AlgorithmRegistryConfig, pool identity.IssuerPool) ([]byte, []byte, error) {
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
		if algorithmRegistry != nil {
			valid, err := algorithmregistry.CheckAlgorithm(pub, crypto.Hash(0), algorithmRegistry)
			if err != nil {
				return nil, nil, fmt.Errorf("checking entry algorithm: %w", err)
			}
			if !valid {
				return nil, nil, &algorithmregistry.UnsupportedAlgorithm{Pub: pub, Alg: crypto.Hash(0)}
			}
		}
		edKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("public key is not an Ed25519 key")
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, nil, errors.New("invalid signature length, must be 64 bytes for Ed25519")
		}

		payload := computeSignaturePayload(req)

		if !ed25519.Verify(edKey, payload, sig) {
			return nil, nil, errors.New("invalid signature")
		}

		// Canonicalize the public key for hashing
		canonicalPubKey, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		rootOfTrust := append([]byte("Ed25519"), canonicalPubKey...)
		rootOfTrustHash := sha256.Sum256(rootOfTrust)

		var extraData []byte
		if contextBytes := cred.PublicKey.GetContext(); len(contextBytes) > 0 {
			extraData = fmt.Appendf(nil, "%s:%s", ContextKeyName, hex.EncodeToString(contextBytes))
		}
		return computeLeaf(req, rootOfTrustHash[:], nil), extraData, nil

	case *pb.IdentityRequestV001_Oidc:
		issuer, claims, err := extractOIDCClaims(ctx, cred.Oidc.GetToken(), pool)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract OIDC claims: %w", err)
		}

		var extraData []byte
		if len(claims) > 0 {
			keys := make([]string, 0, len(claims))
			for k := range claims {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			contextPairs := make([]string, 0, len(keys))
			for _, k := range keys {
				contextPairs = append(contextPairs, fmt.Sprintf("%s:%s", k, claims[k]))
			}
			extraData = []byte(strings.Join(contextPairs, "\n"))
		}

		rootOfTrustHash := sha256.Sum256([]byte(issuer))
		return computeLeaf(req, rootOfTrustHash[:], claims), extraData, nil

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
	leafBytes, _, err := ToLogEntry(context.Background(), req, nil, nil)
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(leafBytes), nil
}

// ToOIDCEntryHash reconstructs the OIDC identity log entry from its message
// hash and claims map, and returns its entry hash. The claims map must contain
// a non-empty "issuer" key.
func ToOIDCEntryHash(message []byte, claims map[string]string) ([]byte, error) {
	issuer := claims["issuer"]
	if issuer == "" {
		return nil, errors.New("issuer claim is missing or empty")
	}
	if len(message) != sha256.Size {
		return nil, errors.New("invalid message hash size, must be 32 bytes")
	}
	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_Oidc{
			Oidc: &pb.OidcCredential{},
		},
		Message: message,
	}
	rootOfTrustHash := sha256.Sum256([]byte(issuer))
	leafBytes := computeLeaf(req, rootOfTrustHash[:], claims)
	return rfc6962.DefaultHasher.HashLeaf(leafBytes), nil
}

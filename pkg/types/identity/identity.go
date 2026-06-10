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
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	SpecDomainSeparatorV1 = "c2sp.org/identity-transparency/v1"
	LeafVersionV1         = byte(0x01)
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
	default:
		return errors.New("unsupported or missing credential type")
	}

	if len(req.GetMessage()) != sha256.Size {
		return errors.New("invalid message hash size, must be 32 bytes")
	}
	if len(req.GetContext()) > 20 {
		return errors.New("too many context strings (max 20)")
	}

	seenKeys := make(map[string]bool)
	for _, entry := range req.GetContext() {
		if len(entry.GetKey()) != sha256.Size {
			return errors.New("invalid context key hash size, must be 32 bytes")
		}
		if len(entry.GetValue()) != sha256.Size {
			return errors.New("invalid context value hash size, must be 32 bytes")
		}
		kStr := string(entry.GetKey())
		if seenKeys[kStr] {
			return errors.New("duplicate context key")
		}
		seenKeys[kStr] = true
	}

	return nil
}

// sortContext sorts a list of ContextEntry elements by their Key.
// It returns a newly allocated sorted slice to avoid mutating the request.
func sortContext(context []*pb.ContextEntry) []*pb.ContextEntry {
	sorted := make([]*pb.ContextEntry, len(context))
	copy(sorted, context)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].GetKey(), sorted[j].GetKey()) < 0
	})
	return sorted
}

func computeSignaturePayload(req *pb.IdentityRequestV001, sortedContext []*pb.ContextEntry) []byte {
	payload := []byte(SpecDomainSeparatorV1)
	payload = append(payload, 0x00)

	msgHash := sha256.Sum256(req.GetMessage())
	payload = append(payload, msgHash[:]...)

	for _, entry := range sortedContext {
		kDoubleHash := sha256.Sum256(entry.GetKey())
		vDoubleHash := sha256.Sum256(entry.GetValue())
		payload = append(payload, kDoubleHash[:]...)
		payload = append(payload, vDoubleHash[:]...)
	}

	return payload
}

func computeLeafHash(req *pb.IdentityRequestV001, sortedContext []*pb.ContextEntry, rootPubKeyHash []byte) []byte {
	leaf := []byte{LeafVersionV1}

	msgHash := sha256.Sum256(req.GetMessage())
	leaf = append(leaf, msgHash[:]...)

	leaf = append(leaf, rootPubKeyHash...)

	for _, entry := range sortedContext {
		kDoubleHash := sha256.Sum256(entry.GetKey())
		vDoubleHash := sha256.Sum256(entry.GetValue())
		leaf = append(leaf, kDoubleHash[:]...)
		leaf = append(leaf, vDoubleHash[:]...)
	}

	var sig []byte
	if cred, ok := req.Credential.(*pb.IdentityRequestV001_PublicKey); ok {
		sig = cred.PublicKey.GetSignature()
	}
	sigHash := sha256.Sum256(sig)
	leaf = append(leaf, sigHash[:]...)

	return leaf
}

// ToLogEntry reconstructs the leaf bytes from bundle-signed inputs.
// It validates the signature and returns the unhashed leaf format.
func ToLogEntry(req *pb.IdentityRequestV001) ([]byte, error) {
	if err := validate(req); err != nil {
		return nil, err
	}
	sortedContext := sortContext(req.GetContext())

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
	edKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an Ed25519 key")
	}

	payload := computeSignaturePayload(req, sortedContext)

	if !ed25519.Verify(edKey, payload, sig) {
		return nil, errors.New("invalid signature")
	}

	rootOfTrust := append([]byte("Ed25519"), pubKey...)
	rootPubKeyHash := sha256.Sum256(rootOfTrust)
	return computeLeafHash(req, sortedContext, rootPubKeyHash[:]), nil
}

// ToEntryHash reconstructs the identity log entry from bundle-signed
// inputs and returns its entry hash.
func ToEntryHash(publicKey []byte, signature []byte, message []byte, context map[string]string) ([]byte, error) {
	var ctxEntries []*pb.ContextEntry
	for k, v := range context {
		keyBytes, err := hex.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("invalid context key hex: %w", err)
		}
		valBytes, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid context value hex: %w", err)
		}
		ctxEntries = append(ctxEntries, &pb.ContextEntry{
			Key:   keyBytes,
			Value: valBytes,
		})
	}

	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: publicKey,
				Signature: signature,
			},
		},
		Message: message,
		Context: ctxEntries,
	}
	leafBytes, err := ToLogEntry(req)
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(leafBytes), nil
}

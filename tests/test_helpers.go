//
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

//go:build e2e

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	dsset "github.com/sigstore/rekor-tiles/v2/pkg/types/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

// artifactDigest generates a test artifact digest for the given index
func artifactDigest(idx uint64) []byte {
	baseArtifact := "testartifact"
	artifact := []byte(fmt.Sprintf("%s%d", baseArtifact, idx))
	digest := sha256.Sum256(artifact)
	return digest[:]
}

// genKeys generates an ECDSA P256 key pair for testing
func genKeys() (*ecdsa.PrivateKey, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

// newHashedRekordRequest creates a HashedRekord request for testing
func newHashedRekordRequest(privKey *ecdsa.PrivateKey, pubKey []byte, idx uint64) (*pb.HashedRekordRequestV002, error) {
	digest := artifactDigest(idx)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}
	return &pb.HashedRekordRequestV002{
		Signature: &pb.Signature{
			Content: sig,
			Verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{
						RawBytes: pubKey,
					},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
		Digest: digest,
	}, nil
}

// newDSSEEnvelope creates a DSSE envelope for testing
func newDSSEEnvelope(privKey *ecdsa.PrivateKey) (*pbdsse.Envelope, error) {
	ecdsaSigner, err := signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	envelopeSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: ecdsaSigner,
	})
	if err != nil {
		return nil, err
	}
	payload := "payload"
	payloadType := "application/vnd.in-toto+json"
	envelope, err := envelopeSigner.SignPayload(context.Background(), payloadType, []byte(payload))
	if err != nil {
		return nil, err
	}
	return dsset.ToProto(envelope)
}

// newDSSERequest creates a DSSE request for testing
func newDSSERequest(privKey *ecdsa.PrivateKey, pubKey []byte) (*pb.DSSERequestV002, error) {
	envelope, err := newDSSEEnvelope(privKey)
	if err != nil {
		return nil, err
	}
	return &pb.DSSERequestV002{
		Envelope: envelope,
		Verifiers: []*pb.Verifier{
			{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{
						RawBytes: pubKey,
					},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
	}, nil
}

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

package hashedrekord

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/protobuf/encoding/protojson"
)

// testCertDER returns DER bytes for a short-lived self-signed P-256 ECDSA
// certificate suitable for populating a pb.Verifier_X509Certificate oneof. The
// leaf hash is only sensitive to the raw bytes, so the cert content is
// otherwise unimportant.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leafhash-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	return der
}

// TestReconstructLeafHashRoundTrip asserts that the leaf hash produced by
// ReconstructLeafHash matches the leaf hash an inlined server-side pipeline
// (protojson.Marshal -> jsoncanonicalizer.Transform -> rfc6962 HashLeaf,
// mirroring internal/server/service.go) computes over an equivalent
// HashedRekordLogEntryV002. This pins the function to the encoding the log
// actually commits to per rekor-v2-spec §6.1.4 "Recompute the leaf". Both
// verifier oneof variants (PublicKey and X509Certificate) are exercised so the
// protojson serialization of each is locked in.
func TestReconstructLeafHashRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	sig := []byte("test-signature-bytes")

	for _, tc := range []struct {
		name     string
		verifier *pb.Verifier
	}{
		{
			name: "public key",
			verifier: &pb.Verifier{
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{RawBytes: []byte("test-raw-public-key")},
				},
			},
		},
		{
			name: "x509 certificate",
			verifier: &pb.Verifier{
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				Verifier: &pb.Verifier_X509Certificate{
					X509Certificate: &v1.X509Certificate{RawBytes: testCertDER(t)},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReconstructLeafHash(digest, &pb.Signature{Content: sig, Verifier: tc.verifier})
			assert.NoError(t, err)

			entry := &pb.Entry{
				Kind:       "hashedrekord",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_HashedRekordV002{
						HashedRekordV002: &pb.HashedRekordLogEntryV002{
							Data: &v1.HashOutput{Digest: digest, Algorithm: v1.HashAlgorithm_SHA2_256},
							Signature: &pb.Signature{
								Content:  sig,
								Verifier: tc.verifier,
							},
						},
					},
				},
			}
			serialized, err := protojson.Marshal(entry)
			assert.NoError(t, err)
			canonicalized, err := jsoncanonicalizer.Transform(serialized)
			assert.NoError(t, err)
			want := rfc6962.DefaultHasher.HashLeaf(canonicalized)

			assert.Equal(t, want, got)
		})
	}
}

// TestReconstructLeafHashChangesWithInputs ensures every bundle-signed input
// (digest, signature, verifier raw bytes, key details, oneof variant) feeds
// into the leaf hash. Any tampering with these inputs must flip the leaf and
// surface as an inclusion-proof failure in the verifier, which is the core
// guarantee rekor-v2-spec §6.1.4 leans on. KeyDetails also exercises the
// registry-driven HashOutput.Algorithm derivation; the oneof-variant row
// confirms PublicKey and X509Certificate are not interchangeable even when
// their raw bytes match.
func TestReconstructLeafHashChangesWithInputs(t *testing.T) {
	type inputs struct {
		digest     []byte
		sig        []byte
		verifierRB []byte
		keyDetails v1.PublicKeyDetails
		asCert     bool
	}
	base := inputs{
		digest:     bytes.Repeat([]byte{0xab}, 32),
		sig:        []byte("test-signature-bytes"),
		verifierRB: []byte("test-raw-public-key"),
		keyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
	}
	hash := func(in inputs) []byte {
		verifier := &pb.Verifier{KeyDetails: in.keyDetails}
		if in.asCert {
			verifier.Verifier = &pb.Verifier_X509Certificate{
				X509Certificate: &v1.X509Certificate{RawBytes: in.verifierRB},
			}
		} else {
			verifier.Verifier = &pb.Verifier_PublicKey{
				PublicKey: &pb.PublicKey{RawBytes: in.verifierRB},
			}
		}
		h, err := ReconstructLeafHash(in.digest, &pb.Signature{Content: in.sig, Verifier: verifier})
		assert.NoError(t, err)
		return h
	}
	baseHash := hash(base)

	for _, tc := range []struct {
		name   string
		mutate func(*inputs)
	}{
		{"digest", func(in *inputs) { in.digest = bytes.Repeat([]byte{0xcd}, 32) }},
		{"signature", func(in *inputs) { in.sig = []byte("different-signature") }},
		{"verifier raw bytes", func(in *inputs) { in.verifierRB = []byte("different-key") }},
		{"verifier key details", func(in *inputs) { in.keyDetails = v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384 }},
		{"verifier oneof variant", func(in *inputs) { in.asCert = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			assert.NotEqual(t, baseHash, hash(mutated), "leaf hash should change when %s changes", tc.name)
		})
	}
}

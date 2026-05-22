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

package hashedrekord

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-test/deep"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor-tiles/v2/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	note "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	b64EncodedSignature = "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"
	hexEncodedDigest    = "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"
	pemPublicKey        = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p
2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END PUBLIC KEY-----`
	pemx509Cert = `-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIUbzTFcv75teYBpaXsDOoYUv5GgWgwCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEaMBgGA1UEAwwRdGVzdC5zaWdzdG9yZS5k
ZXYwIBcNMjUwMzI3MTc1MDQ2WhgPMjEyNTAzMDMxNzUwNDZaMGExCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQxGjAYBgNVBAMMEXRlc3Quc2lnc3RvcmUuZGV2MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy
/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldaNTMFEwHQYDVR0OBBYE
FJvvzmcqq8f+AiXCgAlE4IgdwTq+MB8GA1UdIwQYMBaAFJvvzmcqq8f+AiXCgAlE
4IgdwTq+MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgAqzN4Noq
eH2jEARoIeXY0SRKnaNhVvullmremGvvd6QCIQDrL1WI3a7m8rlHN/7vvCCGtep1
fRnK+CuN46tvzGu+9A==
-----END CERTIFICATE-----`
	pemPublicKeyP384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhM6AR/E5+rwuiWx5YE07ZpSNlG9NCFLb
m+gjNn0q5uByc7GmCwH3fUF3SFyTDCm6+lm9DMiSQHpFqt1IP6HpnAzMwseTOsS7
cc1SxluRyLGYAJEFcNxc01Y/9cT79mf/
-----END PUBLIC KEY-----`
	b64EncodedSignatureP384 = "MGUCMAq2KPdc07xIaNXOX8xNZGn11HFb5OIL049K1I5loaIiogGUunGwFWh/Ae00YBybNwIxALXYkptfZCa+fUfwIW3rbXWAs7vo+DfMyGPcddXfpej1m4i3z+4vL8OJtnrV6kc7lg=="
	hexEncodedDigest384     = "fe23e15e1b7ee8f48a7f878fedbee8f72a57fdf7c6141ddb0b00d23056c9da30e6c0c51588f0f888c830cfce8f29604c"
)

func TestToLogEntry(t *testing.T) {
	block, rest := pem.Decode([]byte(pemPublicKey))
	if len(rest) != 0 {
		t.Fatal("public key decoding had extra data")
	}
	publicKey := block.Bytes

	block, rest = pem.Decode([]byte(pemx509Cert))
	if len(rest) != 0 {
		t.Fatal("certificate decoding had extra data")
	}
	x509Cert := block.Bytes

	block, rest = pem.Decode([]byte(pemPublicKeyP384))
	if len(rest) != 0 {
		t.Fatal("ECDSA-P384 public key decoding had extra data")
	}
	publicKeyP384 := block.Bytes

	tests := []struct {
		name              string
		hashedrekord      *pb.HashedRekordRequestV002
		allowedAlgorithms []v1.PublicKeyDetails
		expectErr         error
		expectedEntry     *pb.Entry
	}{
		{
			name: "valid hashedrekord",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectedEntry: &pb.Entry{
				Kind:       "hashedrekord",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_HashedRekordV002{
						HashedRekordV002: &pb.HashedRekordLogEntryV002{
							Data: &v1.HashOutput{
								Digest:    hexDecodeOrDie(t, hexEncodedDigest),
								Algorithm: v1.HashAlgorithm_SHA2_256,
							},
							Signature: &pb.Signature{
								Content: b64DecodeOrDie(t, b64EncodedSignature),
								Verifier: &pb.Verifier{
									Verifier: &pb.Verifier_PublicKey{
										PublicKey: &pb.PublicKey{
											RawBytes: []byte(publicKey),
										},
									},
									KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "missing signature",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectErr: fmt.Errorf("missing signature"),
		},
		{
			name: "missing verifier",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectErr: fmt.Errorf("missing verifier"),
		},
		{
			name: "missing digest",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("missing digest"),
		},
		{
			name: "invalid verifier",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: []byte("sig"),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: []byte("digest"),
			},
			expectErr: fmt.Errorf("invalid verifier"),
		},
		{
			name: "invalid signature",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: []byte("foobar"),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectErr: fmt.Errorf("verifying signature: "),
		},
		{
			name: "valid hashedrekord with X.509 cert",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_X509Certificate{
							X509Certificate: &v1.X509Certificate{
								RawBytes: []byte(x509Cert),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectedEntry: &pb.Entry{
				Kind:       "hashedrekord",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_HashedRekordV002{
						HashedRekordV002: &pb.HashedRekordLogEntryV002{
							Data: &v1.HashOutput{
								Digest:    hexDecodeOrDie(t, hexEncodedDigest),
								Algorithm: v1.HashAlgorithm_SHA2_256,
							},
							Signature: &pb.Signature{
								Content: b64DecodeOrDie(t, b64EncodedSignature),
								Verifier: &pb.Verifier{
									Verifier: &pb.Verifier_X509Certificate{
										X509Certificate: &v1.X509Certificate{
											RawBytes: []byte(x509Cert),
										},
									},
									KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "mismatched key algorithm",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			allowedAlgorithms: []v1.PublicKeyDetails{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, v1.PublicKeyDetails_PKIX_ED25519_PH},
			expectErr:         fmt.Errorf("unsupported entry algorithm for ECDSA key, curve P-256, digest SHA-256"),
		},
		{
			name: "valid hashedrekord with different algorithm",
			hashedrekord: &pb.HashedRekordRequestV002{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignatureP384),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKeyP384),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
					},
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest384),
			},
			expectedEntry: &pb.Entry{
				Kind:       "hashedrekord",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_HashedRekordV002{
						HashedRekordV002: &pb.HashedRekordLogEntryV002{
							Data: &v1.HashOutput{
								Digest:    hexDecodeOrDie(t, hexEncodedDigest384),
								Algorithm: v1.HashAlgorithm_SHA2_384,
							},
							Signature: &pb.Signature{
								Content: b64DecodeOrDie(t, b64EncodedSignatureP384),
								Verifier: &pb.Verifier{
									Verifier: &pb.Verifier_PublicKey{
										PublicKey: &pb.PublicKey{
											RawBytes: []byte(publicKeyP384),
										},
									},
									KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allowedAlgs := test.allowedAlgorithms
			if allowedAlgs == nil {
				allowedAlgs = []v1.PublicKeyDetails{v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384}
			}
			algReg, err := signature.NewAlgorithmRegistryConfig(allowedAlgs)
			if err != nil {
				t.Fatal(err)
			}
			entry, gotErr := ToLogEntry(test.hashedrekord, algReg)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
				if diff := deep.Equal(test.expectedEntry, entry); diff != nil {
					t.Errorf("ToLogEntry() mismatch (-want +got):\n%s", diff)
				}
			} else {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

func hexDecodeOrDie(t *testing.T, hash string) []byte {
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func b64DecodeOrDie(t *testing.T, msg string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func testCertDER(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	return der
}

func TestToEntryHashRoundTrip(t *testing.T) {
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
			got, err := ToEntryHash(digest, &pb.Signature{Content: sig, Verifier: tc.verifier})
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

func TestToEntryHashChangesWithInputs(t *testing.T) {
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
		h, err := ToEntryHash(in.digest, &pb.Signature{Content: in.sig, Verifier: verifier})
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
			assert.NotEqual(t, baseHash, hash(mutated), "entry hash should change when %s changes", tc.name)
		})
	}
}

func TestToEntryHashEndToEnd(t *testing.T) {
	hostname := "rekor.localhost"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256([]byte("end-to-end test payload"))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, payloadDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	req := &pb.HashedRekordRequestV002{
		Digest: payloadDigest[:],
		Signature: &pb.Signature{
			Content: sig,
			Verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{RawBytes: pubKeyDER},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
	}

	algReg, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256})
	if err != nil {
		t.Fatal(err)
	}
	logEntry, err := ToLogEntry(req, algReg)
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := protojson.Marshal(logEntry)
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(serialized)
	if err != nil {
		t.Fatal(err)
	}
	serverEntryHash := rfc6962.DefaultHasher.HashLeaf(canonicalized)

	cpSV, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, cpSV)
	if err != nil {
		t.Fatal(err)
	}
	noteVerifier, err := rekornote.NewNoteVerifier(hostname, cpSV)
	if err != nil {
		t.Fatal(err)
	}
	cpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   1,
		Hash:   serverEntryHash,
	}.Marshal()
	signedCp, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}
	tle := &pbs.TransparencyLogEntry{
		LogIndex: 0,
		InclusionProof: &pbs.InclusionProof{
			LogIndex: 0,
			TreeSize: 1,
			Hashes:   [][]byte{},
			Checkpoint: &pbs.Checkpoint{
				Envelope: string(signedCp),
			},
		},
	}

	clientEntryHash, err := ToEntryHash(req.Digest, req.Signature)
	assert.NoError(t, err)
	assert.Equal(t, serverEntryHash, clientEntryHash, "client-reconstructed entry hash must equal server-canonicalized entry hash")

	assert.NoError(t, verify.VerifyLogEntryWithHash(tle, noteVerifier, clientEntryHash))

	tamperedDigest := append([]byte(nil), req.Digest...)
	tamperedDigest[0] ^= 0x01
	tamperedEntryHash, err := ToEntryHash(tamperedDigest, req.Signature)
	assert.NoError(t, err)
	assert.NotEqual(t, clientEntryHash, tamperedEntryHash)
	assert.Error(t, verify.VerifyLogEntryWithHash(tle, noteVerifier, tamperedEntryHash))
}

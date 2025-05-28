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

package dsse

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	dsset "github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	pemPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE850nB+WrwXzivt7yFbhFKw/8M2pa
qSTHiQhkA4/0ZAsJtmzn/v4HdeZKTCQcsHq5IwM/LtbmEdv9ChO9M3cg9g==
-----END PUBLIC KEY-----`
	pemx509Cert = `-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIUWi7MFKfQ+/QSDFb0RjUBmyvOCu0wCgYIKoZIzj0EAwIw
YTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEaMBgGA1UEAwwRdGVzdC5zaWdzdG9yZS5k
ZXYwIBcNMjUwMzI3MTgwNjAwWhgPMjEyNTAzMDMxODA2MDBaMGExCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQxGjAYBgNVBAMMEXRlc3Quc2lnc3RvcmUuZGV2MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEYJSwH/PInqkK+Um3iMPswCJg9SgypKpWY9onmsAJ
Sj/nGF5ZiEOLfD7KJ747MtBrQ/lRJTXW5aEs9brVKOwrXqNTMFEwHQYDVR0OBBYE
FAFlFaiDwXiV0qh7PILjNrp1zdYGMB8GA1UdIwQYMBaAFAFlFaiDwXiV0qh7PILj
Nrp1zdYGMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALrgqHZR
5glHunRCQ60XVtn7xEUvHIkyWdhQvocrEQ+KAiAlucBaXZ5NQ9viz1ATrdSyuj+a
atI4zS+80vbts4NEFA==
-----END CERTIFICATE-----`
	pemPublicKeyP384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhM6AR/E5+rwuiWx5YE07ZpSNlG9NCFLb
m+gjNn0q5uByc7GmCwH3fUF3SFyTDCm6+lm9DMiSQHpFqt1IP6HpnAzMwseTOsS7
cc1SxluRyLGYAJEFcNxc01Y/9cT79mf/
-----END PUBLIC KEY-----`
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

	var payload = []byte("payload")
	var payloadHash = sha256.Sum256(payload)
	var keySignature = b64DecodeOrDie(t, "MEUCIQCSWas1Y9bI7aDNrBdHlzrFH8ch7B7IM+pJK86mtjkbJAIgaeCltz6vs20DP2sJ7IBihvcrdqGn3ivuV/KNPlMOetk=")
	var certSignature = b64DecodeOrDie(t, "MEUCIQDoYuLoinEz/gM6B+hEn/0d47lmRDitQ3LfL9vH0sF/gQIgPqVgoBTRsMSPYMXYuJYYCIaTpnuppqQaTSTRn0ubwLI=")
	var keySignatureP384 = b64DecodeOrDie(t, "MGYCMQDdKEzOCt71AzF+KKxrDQgCcPtsnfPZORmPlFZutXFqM8y/fi77sEAOjYkVdc4xxJwCMQC/4JuQ/bDWQV4QzPRA/u03pG49iTUDskoCFIrmabe0XyC9JkY1yyeuNS2LixMCaCI=")

	tests := []struct {
		name              string
		dsse              *pb.DSSERequestV002
		allowedAlgorithms []v1.PublicKeyDetails
		expectErr         error
		expectedEntry     *pb.Entry
	}{
		{
			name: "valid dsse",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   keySignature,
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectedEntry: &pb.Entry{
				Kind:       "dsse",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_DsseV002{
						DsseV002: &pb.DSSELogEntryV002{
							PayloadHash: &v1.HashOutput{
								Algorithm: v1.HashAlgorithm_SHA2_256,
								Digest:    payloadHash[:],
							},
							Signatures: []*pb.Signature{
								{
									Content: keySignature,
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
		},
		{
			name: "missing envelope",
			dsse: &pb.DSSERequestV002{
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("missing envelope"),
		},
		{
			name: "missing verifiers",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   keySignature,
							Keyid: "",
						},
					},
				},
			},
			expectErr: fmt.Errorf("missing verifiers"),
		},
		{
			name: "invalid verifier",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     []byte("payload"),
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   []byte("sig"),
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("invalid verifier"),
		},
		{
			name: "missing signatures",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("envelope missing signatures"),
		},
		{
			name: "empty signatures",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures:  []*dsse.Signature{},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("envelope missing signatures"),
		},
		{
			name: "invalid signature",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   b64DecodeOrDie(t, "Zm9vYmFyCg=="),
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectErr: fmt.Errorf("could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1"),
		},
		{
			name: "valid dsse with X.509 cert",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   certSignature,
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_X509Certificate{
							X509Certificate: &v1.X509Certificate{
								RawBytes: []byte(x509Cert),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			expectedEntry: &pb.Entry{
				Kind:       "dsse",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_DsseV002{
						DsseV002: &pb.DSSELogEntryV002{
							PayloadHash: &v1.HashOutput{
								Algorithm: v1.HashAlgorithm_SHA2_256,
								Digest:    payloadHash[:],
							},
							Signatures: []*pb.Signature{
								{
									Content: certSignature,
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
		},
		{
			name: "mismatched key algorithm",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   keySignature,
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
				},
			},
			allowedAlgorithms: []v1.PublicKeyDetails{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, v1.PublicKeyDetails_PKIX_ED25519_PH},
			expectErr:         fmt.Errorf("unsupported entry algorithm for ECDSA key, curve P-256, digest SHA-256"),
		},
		{
			name: "valid DSSE with multiple signatures, different algorithm",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   keySignature,
							Keyid: "",
						},
						{
							Sig:   keySignatureP384,
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKeyP384),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
					},
				},
			},
			expectedEntry: &pb.Entry{
				Kind:       "dsse",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_DsseV002{
						DsseV002: &pb.DSSELogEntryV002{
							PayloadHash: &v1.HashOutput{
								Algorithm: v1.HashAlgorithm_SHA2_256,
								Digest:    payloadHash[:],
							},
							Signatures: []*pb.Signature{
								{
									Content: keySignature,
									Verifier: &pb.Verifier{
										Verifier: &pb.Verifier_PublicKey{
											PublicKey: &pb.PublicKey{
												RawBytes: []byte(publicKey),
											},
										},
										KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
									},
								},
								{
									Content: keySignatureP384,
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
		},
		{
			// test input is same as "valid DSSE with multiple signatures, different algorithm",
			// but with signature input swapped, to show that response signature order is canonicalized
			name: "valid DSSE with multiple signatures in consistent order",
			dsse: &pb.DSSERequestV002{
				Envelope: &dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
					Signatures: []*dsse.Signature{
						{
							Sig:   keySignatureP384,
							Keyid: "",
						},
						{
							Sig:   keySignature,
							Keyid: "",
						},
					},
				},
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
					},
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKeyP384),
							},
						},
						KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
					},
				},
			},
			expectedEntry: &pb.Entry{
				Kind:       "dsse",
				ApiVersion: "0.0.2",
				Spec: &pb.Spec{
					Spec: &pb.Spec_DsseV002{
						DsseV002: &pb.DSSELogEntryV002{
							PayloadHash: &v1.HashOutput{
								Algorithm: v1.HashAlgorithm_SHA2_256,
								Digest:    payloadHash[:],
							},
							Signatures: []*pb.Signature{
								{
									Content: keySignature,
									Verifier: &pb.Verifier{
										Verifier: &pb.Verifier_PublicKey{
											PublicKey: &pb.PublicKey{
												RawBytes: []byte(publicKey),
											},
										},
										KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
									},
								},
								{
									Content: keySignatureP384,
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
			entry, gotErr := ToLogEntry(test.dsse, algReg)
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

func TestConverters(t *testing.T) {
	tests := []struct {
		name  string
		dsseB []byte
	}{
		{
			name:  "single signature with key ids",
			dsseB: []byte("{\"payload\":\"cGF5bG9hZAo=\",\"payloadType\":\"application/vnd.in-toto+json\",\"signatures\":[{\"sig\":\"c2lnbmF0dXJlCg==\", \"keyid\": \"id1\"}]}"),
		},
		{
			name:  "single signature with no key ids",
			dsseB: []byte("{\"payload\":\"cGF5bG9hZAo=\",\"payloadType\":\"application/vnd.in-toto+json\",\"signatures\":[{\"sig\":\"c2lnbmF0dXJlCg==\"}]}"),
		},
		{
			name:  "multi signature with key ids",
			dsseB: []byte("{\"payload\":\"cGF5bG9hZAo=\",\"payloadType\":\"application/vnd.in-toto+json\",\"signatures\":[{\"sig\":\"c2lnbmF0dXJlCg==\", \"keyid\": \"id1\"}, {\"sig\":\"c2lnbmF0dXJlMgo=\", \"keyid\": \"id2\"}]}"),
		},
	}

	for _, test := range tests {
		env := &dsset.Envelope{}
		if err := json.Unmarshal(test.dsseB, env); err != nil {
			t.Fatal(err)
		}
		protoEnv := &dsse.Envelope{}
		if err := protojson.Unmarshal(test.dsseB, protoEnv); err != nil {
			t.Fatal(err)
		}

		t.Run("testToProto "+test.name, func(t *testing.T) {
			convertedEnv, err := ToProto(env)
			if err != nil {
				t.Fatal(err)
			}
			if diff := deep.Equal(protoEnv, convertedEnv); diff != nil {
				t.Errorf("ToProto() mismatch (-want +got):\n%s", diff)
			}
		})

		t.Run("testFromProto "+test.name, func(t *testing.T) {
			convertedEnv := FromProto(protoEnv)
			if diff := deep.Equal(env, convertedEnv); diff != nil {
				t.Errorf("FromProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}

}

func b64DecodeOrDie(t *testing.T, msg string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

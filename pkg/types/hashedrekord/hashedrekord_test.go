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
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
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
		hashedrekord      *pb.HashedRekordRequestV0_0_2
		allowedAlgorithms []v1.PublicKeyDetails
		expectErr         error
	}{
		{
			name: "valid hashedrekord",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
		},
		{
			name: "missing signature",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
				},
				Digest: hexDecodeOrDie(t, hexEncodedDigest),
			},
			expectErr: fmt.Errorf("missing verifier"),
		},
		{
			name: "missing digest",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
		},
		{
			name: "mismatched key algorithm",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
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
			_, gotErr := ToLogEntry(test.hashedrekord, algReg)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
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

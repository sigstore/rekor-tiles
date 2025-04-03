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
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
)

var (
	b64EncodedSignature = "MEYCIQC59oLS3MsCqm0xCxPOy+8FdQK4RYCZE036s3q1ECfcagIhAJ4ATXlCSdFrklKAS8No0PsAE9uLi37TCbIfRXASJTTb"
	hexEncodedDigest    = "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"
	publicKey           = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p
2D+C5G9xPEsy/PVAo9H0mgS4NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END PUBLIC KEY-----`
	x509Cert = `-----BEGIN CERTIFICATE-----
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
)

func TestToLogEntry(t *testing.T) {
	tests := []struct {
		name         string
		hashedrekord *pb.HashedRekordRequestV0_0_2
		expectErr    error
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
					},
				},
				Data: &v1.HashOutput{
					Digest: hexDecodeOrDie(t, hexEncodedDigest),
				},
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
					},
				},
				Data: &v1.HashOutput{
					Digest: hexDecodeOrDie(t, hexEncodedDigest),
				},
			},
			expectErr: fmt.Errorf("missing signature"),
		},
		{
			name: "missing verifier",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
				},
				Data: &v1.HashOutput{
					Digest: hexDecodeOrDie(t, hexEncodedDigest),
				},
			},
			expectErr: fmt.Errorf("missing verifier"),
		},
		{
			name: "missing data",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
					},
				},
			},
			expectErr: fmt.Errorf("missing data"),
		},
		{
			name: "missing data digest",
			hashedrekord: &pb.HashedRekordRequestV0_0_2{
				Signature: &pb.Signature{
					Content: b64DecodeOrDie(t, b64EncodedSignature),
					Verifier: &pb.Verifier{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
					},
				},
				Data: &v1.HashOutput{},
			},
			expectErr: fmt.Errorf("missing data digest"),
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
					},
				},
				Data: &v1.HashOutput{
					Digest: hexDecodeOrDie(t, hexEncodedDigest),
				},
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
					},
				},
				Data: &v1.HashOutput{
					Digest: hexDecodeOrDie(t, hexEncodedDigest),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, gotErr := ToLogEntry(test.hashedrekord)
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

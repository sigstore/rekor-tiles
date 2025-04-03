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
	"fmt"
	"testing"

	"github.com/go-test/deep"
	dsset "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
)

var (
	publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE850nB+WrwXzivt7yFbhFKw/8M2pa
qSTHiQhkA4/0ZAsJtmzn/v4HdeZKTCQcsHq5IwM/LtbmEdv9ChO9M3cg9g==
-----END PUBLIC KEY-----`
	x509Cert = `-----BEGIN CERTIFICATE-----
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
)

func TestToLogEntry(t *testing.T) {
	var payload = []byte("payload")
	var payloadHash = sha256.Sum256(payload)
	var keySignature = b64DecodeOrDie(t, "MEUCIQCSWas1Y9bI7aDNrBdHlzrFH8ch7B7IM+pJK86mtjkbJAIgaeCltz6vs20DP2sJ7IBihvcrdqGn3ivuV/KNPlMOetk=")
	var certSignature = b64DecodeOrDie(t, "MEUCIQDoYuLoinEz/gM6B+hEn/0d47lmRDitQ3LfL9vH0sF/gQIgPqVgoBTRsMSPYMXYuJYYCIaTpnuppqQaTSTRn0ubwLI=")
	tests := []struct {
		name          string
		dsse          *pb.DSSERequestV0_0_2
		expectErr     error
		expectedEntry *pb.DSSELogEntryV0_0_2
	}{
		{
			name: "valid dsse",
			dsse: &pb.DSSERequestV0_0_2{
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
					},
				},
			},
			expectedEntry: &pb.DSSELogEntryV0_0_2{
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
						},
					},
				},
			},
		},
		{
			name: "missing envelope",
			dsse: &pb.DSSERequestV0_0_2{
				Verifiers: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
					},
				},
			},
			expectErr: fmt.Errorf("missing envelope"),
		},
		{
			name: "missing verifiers",
			dsse: &pb.DSSERequestV0_0_2{
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
			name: "missing signatures",
			dsse: &pb.DSSERequestV0_0_2{
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
					},
				},
			},
			expectErr: fmt.Errorf("envelope missing signatures"),
		},
		{
			name: "empty signatures",
			dsse: &pb.DSSERequestV0_0_2{
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
					},
				},
			},
			expectErr: fmt.Errorf("envelope missing signatures"),
		},
		{
			name: "invalid signature",
			dsse: &pb.DSSERequestV0_0_2{
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
					},
				},
			},
			expectErr: fmt.Errorf("could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1"),
		},
		{
			name: "valid dsse with X.509 cert",
			dsse: &pb.DSSERequestV0_0_2{
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
					},
				},
			},
			expectedEntry: &pb.DSSELogEntryV0_0_2{
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
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, gotErr := ToLogEntry(test.dsse)
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

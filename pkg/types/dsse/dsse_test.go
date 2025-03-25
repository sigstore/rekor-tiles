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
	"fmt"
	"testing"

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

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		dsse      *pb.DSSERequest
		expectErr error
	}{
		{
			name: "valid dsse",
			dsse: &pb.DSSERequest{
				Envelope: "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"cGF5bG9hZA==\",\"signatures\":[{\"keyid\":\"\",\"sig\":\"MEUCIQCSWas1Y9bI7aDNrBdHlzrFH8ch7B7IM+pJK86mtjkbJAIgaeCltz6vs20DP2sJ7IBihvcrdqGn3ivuV/KNPlMOetk=\"}]}",
				Verifier: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte(publicKey),
							},
						},
					},
				},
			},
		},
		{
			name: "missing envelope",
			dsse: &pb.DSSERequest{
				Verifier: []*pb.Verifier{
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
			dsse: &pb.DSSERequest{
				Envelope: "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"cGF5bG9hZA==\",\"signatures\":[{\"keyid\":\"\",\"sig\":\"MEUCIQCSWas1Y9bI7aDNrBdHlzrFH8ch7B7IM+pJK86mtjkbJAIgaeCltz6vs20DP2sJ7IBihvcrdqGn3ivuV/KNPlMOetk=\"}]}",
			},
			expectErr: fmt.Errorf("missing verifiers"),
		},
		{
			name: "missing signatures",
			dsse: &pb.DSSERequest{
				Envelope: "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"cGF5bG9hZA==\"}",
				Verifier: []*pb.Verifier{
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
			dsse: &pb.DSSERequest{
				Envelope: "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"cGF5bG9hZA==\",\"signatures\":[{\"keyid\":\"\",\"sig\":\"Zm9vYmFyCg==\"}]}",
				Verifier: []*pb.Verifier{
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
			dsse: &pb.DSSERequest{
				Envelope: "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"cGF5bG9hZA==\",\"signatures\":[{\"keyid\":\"\",\"sig\":\"MEUCIQDoYuLoinEz/gM6B+hEn/0d47lmRDitQ3LfL9vH0sF/gQIgPqVgoBTRsMSPYMXYuJYYCIaTpnuppqQaTSTRn0ubwLI=\"}]}",
				Verifier: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_X509Certificate{
							X509Certificate: &v1.X509Certificate{
								RawBytes: []byte(x509Cert),
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := Validate(test.dsse)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
			} else {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

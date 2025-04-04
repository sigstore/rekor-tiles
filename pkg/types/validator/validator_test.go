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

package validator

import (
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		verifier  *pb.Verifier
		expectErr error
	}{
		{
			name: "valid public key verifier",
			verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{
						RawBytes: []byte("abcd"),
					},
				},
			},
		},
		{
			name: "valid x.509 verifier",
			verifier: &pb.Verifier{
				Verifier: &pb.Verifier_X509Certificate{
					X509Certificate: &v1.X509Certificate{
						RawBytes: []byte("abcd"),
					},
				},
			},
		},
		{
			name:      "no valid verifier",
			verifier:  &pb.Verifier{},
			expectErr: fmt.Errorf("missing signature public key or X.509 certificate"),
		},
		{
			name: "public key missing content",
			verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{},
				},
			},
			expectErr: fmt.Errorf("missing public key raw bytes"),
		},
		{
			name: "x.509 cert missing content",
			verifier: &pb.Verifier{
				Verifier: &pb.Verifier_X509Certificate{
					X509Certificate: &v1.X509Certificate{},
				},
			},
			expectErr: fmt.Errorf("missing X.509 certificate raw bytes"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := Validate(test.verifier)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
			} else {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

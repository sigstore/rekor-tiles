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
	"fmt"
	"testing"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name         string
		hashedrekord *pb.HashedRekordRequest
		expectErr    error
	}{
		{
			name: "valid hashedrekord",
			hashedrekord: &pb.HashedRekordRequest{
				Signature: []byte("abcd"),
				Verifier: &pb.Verifier{
					Verifier: &pb.Verifier_PublicKey{
						PublicKey: &pb.PublicKey{
							RawBytes: []byte("3456"),
						},
					},
				},
				Data: &v1.HashOutput{
					Digest: []byte("ef12"),
				},
			},
		},
		{
			name: "missing signature",
			hashedrekord: &pb.HashedRekordRequest{
				Verifier: &pb.Verifier{
					Verifier: &pb.Verifier_PublicKey{
						PublicKey: &pb.PublicKey{
							RawBytes: []byte("3456"),
						},
					},
				},
				Data: &v1.HashOutput{
					Digest: []byte("ef12"),
				},
			},
			expectErr: fmt.Errorf("missing signature"),
		},
		{
			name: "missing verifier",
			hashedrekord: &pb.HashedRekordRequest{
				Signature: []byte("abcd"),
				Data: &v1.HashOutput{
					Digest: []byte("ef12"),
				},
			},
			expectErr: fmt.Errorf("missing verifier"),
		},
		{
			name: "missing data",
			hashedrekord: &pb.HashedRekordRequest{
				Signature: []byte("abcd"),
				Verifier: &pb.Verifier{
					Verifier: &pb.Verifier_PublicKey{
						PublicKey: &pb.PublicKey{
							RawBytes: []byte("3456"),
						},
					},
				},
			},
			expectErr: fmt.Errorf("missing data"),
		},
		{
			name: "missing data digest",
			hashedrekord: &pb.HashedRekordRequest{
				Signature: []byte("abcd"),
				Verifier: &pb.Verifier{
					Verifier: &pb.Verifier_PublicKey{
						PublicKey: &pb.PublicKey{
							RawBytes: []byte("3456"),
						},
					},
				},
				Data: &v1.HashOutput{},
			},
			expectErr: fmt.Errorf("missing data digest"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := Validate(test.hashedrekord)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
			} else {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

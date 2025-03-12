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

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/stretchr/testify/assert"
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
				Envelope: "dsse",
				Verifier: []*pb.Verifier{
					{
						Verifier: &pb.Verifier_PublicKey{
							PublicKey: &pb.PublicKey{
								RawBytes: []byte("3456"),
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
								RawBytes: []byte("3456"),
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
				Envelope: "dsse",
			},
			expectErr: fmt.Errorf("missing verifiers"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := Validate(test.dsse)
			if test.expectErr == nil {
				assert.NoError(t, gotErr)
			} else {
				assert.Errorf(t, gotErr, test.expectErr.Error())
			}
		})
	}
}

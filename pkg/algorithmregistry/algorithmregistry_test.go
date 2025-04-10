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

package algorithmregistry

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlgorithmRegistry(t *testing.T) {
	tests := []struct {
		name             string
		algorithmOptions []string
		wantErr          bool
	}{
		{
			name:             "defaults",
			algorithmOptions: nil,
		},
		{
			name: "valid algorithms",
			algorithmOptions: []string{
				"ecdsa-sha2-384-nistp384",
				"ecdsa-sha2-512-nistp521",
				"ed25519",
				"rsa-sign-pkcs1-3072-sha256",
				"rsa-sign-pkcs1-4096-sha256",
			},
		},
		{
			name: "invalid algorithms",
			algorithmOptions: []string{
				"foo",
				"bar",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := AlgorithmRegistry(test.algorithmOptions)
			if test.wantErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			assert.NotNil(t, got)
		})
	}
}

func TestSelectHashAlgorithm(t *testing.T) {
	testCases := []struct {
		name           string
		inputAlgs      []crypto.Hash
		expectedHash   crypto.Hash
		expectErr      bool
		expectedErrMsg string
	}{
		{
			name:         "Select strongest (SHA512)",
			inputAlgs:    []crypto.Hash{crypto.SHA256, crypto.SHA512, crypto.SHA384},
			expectedHash: crypto.SHA512,
			expectErr:    false,
		},
		{
			name:         "Select mid (SHA384)",
			inputAlgs:    []crypto.Hash{crypto.SHA256, crypto.SHA384},
			expectedHash: crypto.SHA384,
			expectErr:    false,
		},
		{
			name:         "Select only one",
			inputAlgs:    []crypto.Hash{crypto.SHA256},
			expectedHash: crypto.SHA256,
			expectErr:    false,
		},
		{
			name:         "Input already ordered",
			inputAlgs:    []crypto.Hash{crypto.SHA512, crypto.SHA384, crypto.SHA256},
			expectedHash: crypto.SHA512,
			expectErr:    false,
		},
		{
			name:         "Contains unknown algorithm (MD5)",
			inputAlgs:    []crypto.Hash{crypto.MD5, crypto.SHA256, crypto.SHA384},
			expectedHash: crypto.SHA384,
			expectErr:    false,
		},
		{
			name:           "Only unknown algorithms",
			inputAlgs:      []crypto.Hash{crypto.MD5, crypto.SHA1},
			expectedHash:   crypto.Hash(0),
			expectErr:      true,
			expectedErrMsg: "no known hash algorithms provided",
		},
		{
			name:         "Duplicate algorithms",
			inputAlgs:    []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA256, crypto.SHA512, crypto.SHA384},
			expectedHash: crypto.SHA512,
			expectErr:    false,
		},
		{
			name:           "Empty slice",
			inputAlgs:      []crypto.Hash{},
			expectedHash:   crypto.Hash(0),
			expectErr:      true,
			expectedErrMsg: "hash algorithm slice is empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Make a copy, as the function modifies the input slice.
			inputCopy := make([]crypto.Hash, len(tc.inputAlgs))
			copy(inputCopy, tc.inputAlgs)

			actualHash, actualErr := SelectHashAlgorithm(inputCopy)

			if tc.expectErr {
				if actualErr == nil {
					t.Errorf("SelectHashAlgorithm() expected error, but got nil")
					return
				}
				if actualErr.Error() != tc.expectedErrMsg {
					t.Errorf("SelectHashAlgorithm() error = %q, want %q", actualErr.Error(), tc.expectedErrMsg)
				}
				if actualHash != crypto.Hash(0) {
					t.Errorf("SelectHashAlgorithm() expected zero hash value on error, got %v", actualHash)
				}
			} else {
				if actualErr != nil {
					t.Errorf("SelectHashAlgorithm() returned unexpected error: %v", actualErr)
					return
				}
				if actualHash != tc.expectedHash {
					t.Errorf("SelectHashAlgorithm() hash = %v, want %v", actualHash, tc.expectedHash)
				}
			}
		})
	}
}

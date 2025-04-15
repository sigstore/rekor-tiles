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

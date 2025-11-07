//
// Copyright 2025 The Sigstore Authors.
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

package safeint

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSafeInt64(t *testing.T) {
	tests := []struct {
		name      string
		number    any
		expect    *SafeInt64
		expectErr error
	}{
		{
			name:   "small uint",
			number: uint64(42),
			expect: &SafeInt64{u: uint64(42), i: int64(42)},
		},
		{
			name:   "small positive int",
			number: int64(42),
			expect: &SafeInt64{u: uint64(42), i: int64(42)},
		},
		{
			name:      "too large uint",
			number:    uint64(math.MaxUint64 - 77),
			expect:    nil,
			expectErr: fmt.Errorf("exceeded max int64: %d", uint64(math.MaxUint64-77)),
		},
		{
			name:      "too small int",
			number:    int64(-1),
			expect:    nil,
			expectErr: fmt.Errorf("negative integer: -1"),
		},
		{
			name:      "wrong type",
			number:    1,
			expect:    nil,
			expectErr: fmt.Errorf("only uint64 and int64 are supported"),
		},
		{
			name:      "really wrong type",
			number:    "forty-two",
			expect:    nil,
			expectErr: fmt.Errorf("only uint64 and int64 are supported"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewSafeInt64(test.number)
			assert.Equal(t, test.expect, got)
			assert.Equal(t, test.expectErr, gotErr)
		})
	}
}

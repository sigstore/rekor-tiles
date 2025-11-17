//go:build aws

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

package tessera

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDriverAWS(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		config      DriverConfiguration
		expectErr   bool
		errContains string
		skipReason  string
	}{
		{
			name: "no configuration provided",
			config: DriverConfiguration{
				Hostname: "test",
			},
			expectErr:   true,
			errContains: "AWS backend requires",
		},
		{
			name: "AWS configuration incomplete - missing MySQL DSN",
			config: DriverConfiguration{
				Hostname:  "test",
				AWSBucket: "test-bucket",
			},
			expectErr:   true,
			errContains: "AWS backend requires",
		},
		{
			name: "AWS configuration incomplete - missing bucket",
			config: DriverConfiguration{
				Hostname:    "test",
				AWSMySQLDSN: "user:pass@tcp(localhost:3306)/db",
			},
			expectErr:   true,
			errContains: "AWS backend requires",
		},
		{
			name: "AWS configuration complete",
			config: DriverConfiguration{
				Hostname:    "test",
				AWSBucket:   "test-bucket",
				AWSMySQLDSN: "user:pass@tcp(localhost:3306)/db",
			},
			skipReason: "requires AWS credentials and MySQL connectivity",
		},
		{
			name: "AWS configuration with persistent antispam",
			config: DriverConfiguration{
				Hostname:            "test",
				AWSBucket:           "test-bucket",
				AWSMySQLDSN:         "user:pass@tcp(localhost:3306)/db",
				PersistentAntispam:  true,
				ASMaxBatchSize:      100,
				ASPushbackThreshold: 10,
			},
			skipReason: "requires AWS credentials and MySQL connectivity",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skipReason != "" {
				t.Skip(test.skipReason)
			}

			driver, antispam, err := NewDriver(ctx, test.config)

			if test.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
				assert.Nil(t, driver)
				assert.Nil(t, antispam)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, driver)
			}
		})
	}
}

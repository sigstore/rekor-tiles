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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAWSDriver_AWSSDKLoads(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		bucket     string
		mysqlDSN   string
		hostname   string
		skipReason string
	}{
		{
			name:       "configuration with connectivity check",
			bucket:     "test-bucket",
			mysqlDSN:   "user:pass@tcp(localhost:3306)/db",
			hostname:   "test",
			skipReason: "requires AWS credentials and MySQL connectivity",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skipReason != "" {
				t.Skip(test.skipReason)
			}

			driver, err := NewAWSDriver(ctx, test.bucket, test.mysqlDSN, test.hostname)
			require.NoError(t, err)
			assert.NotNil(t, driver)
		})
	}
}

func TestNewAWSAntispam_ConfigValidation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name              string
		mysqlDSN          string
		maxBatchSize      uint
		pushbackThreshold uint
		expectErr         bool
		errContains       string
		skipReason        string
	}{
		{
			name:              "empty DSN",
			mysqlDSN:          "",
			maxBatchSize:      100,
			pushbackThreshold: 10,
			skipReason:        "requires MySQL connectivity",
		},
		{
			name:              "valid configuration requires real MySQL",
			mysqlDSN:          "user:pass@tcp(localhost:3306)/db",
			maxBatchSize:      100,
			pushbackThreshold: 10,
			skipReason:        "requires MySQL connectivity",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skipReason != "" {
				t.Skip(test.skipReason)
			}

			antispam, err := NewAWSAntispam(ctx, test.mysqlDSN, test.maxBatchSize, test.pushbackThreshold)

			if test.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
				assert.Nil(t, antispam)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, antispam)
			}
		})
	}
}

func TestNewAWSDriver_WithRealAWSEnv(t *testing.T) {
	// Skip if not running in AWS backend test environment
	if os.Getenv("TEST_AWS_BACKEND") != "true" {
		t.Skip("skipping AWS driver test; set TEST_AWS_BACKEND=true to run")
	}

	ctx := context.Background()

	// These values match the docker-compose-aws.yml configuration
	bucket := os.Getenv("AWS_BUCKET_NAME")
	if bucket == "" {
		bucket = "rekor-tiles"
	}

	mysqlDSN := os.Getenv("AWS_MYSQL_DSN")
	if mysqlDSN == "" {
		t.Skip("AWS_MYSQL_DSN not set")
	}

	driver, err := NewAWSDriver(ctx, bucket, mysqlDSN, "test-hostname")
	require.NoError(t, err)
	assert.NotNil(t, driver)
}

func TestNewAWSAntispam_WithRealMySQLEnv(t *testing.T) {
	// Skip if not running in AWS backend test environment
	if os.Getenv("TEST_AWS_BACKEND") != "true" {
		t.Skip("skipping AWS antispam test; set TEST_AWS_BACKEND=true to run")
	}

	ctx := context.Background()

	mysqlDSN := os.Getenv("AWS_MYSQL_DSN")
	if mysqlDSN == "" {
		t.Skip("AWS_MYSQL_DSN not set")
	}

	antispam, err := NewAWSAntispam(ctx, mysqlDSN, 100, 10)
	require.NoError(t, err)
	assert.NotNil(t, antispam)
}

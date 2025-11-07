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
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/tessera"
)

func TestAdd(t *testing.T) {
	ctx := context.Background()
	tileHash := hexDecodeOrDie(t, "81bfc09c412c04da53a1b0ddb94dce48d6a24e9ea58987f7d45a04e8007fb3ca")
	readCheckpoint := func(_ context.Context) ([]byte, error) {
		<-time.After(5 * time.Millisecond)
		return []byte(`test.origin
1
gb/AnEEsBNpTobDduU3OSNaiTp6liYf31FoE6AB/s8o=

— test.origin AAAAAW5vb3AKMQpnYi9BbkVFc0JOcFRvYkRkdVUzT1NOYWlUcDZsaVlmMzFGb0U2QUIvczhvPQo=`), nil
	}
	s := storage{
		awaiter: tessera.NewPublicationAwaiter(ctx, readCheckpoint, 10*time.Millisecond),
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return tileHash, nil
		},
	}
	entry := tessera.NewEntry([]byte("stuff"))
	tests := []struct {
		name           string
		addFn          func(context.Context, *tessera.Entry) tessera.IndexFuture
		expectErr      error
		expectLogIndex int64
		expectTreeSize int64
		expectHash     []byte
		expectBody     []byte
	}{
		{
			name: "success",
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0}, nil }
			},
			expectLogIndex: int64(0),
			expectTreeSize: int64(1),
			expectHash:     tileHash,
			expectBody:     []byte("stuff"),
		},
		{
			name: "integration failed",
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0}, fmt.Errorf("server error") }
			},
			expectErr: fmt.Errorf("add entry: await: server error"),
		},
		{
			name: "duplicate entry",
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			expectErr: fmt.Errorf("an equivalent entry already exists in the transparency log with index 0"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s.addFn = test.addFn
			got, gotErr := s.Add(ctx, entry)
			if test.expectErr != nil {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
				return
			}
			assert.NoError(t, gotErr)
			assert.Equal(t, test.expectLogIndex, got.LogIndex)
			assert.Equal(t, test.expectTreeSize, got.InclusionProof.TreeSize)
			assert.Equal(t, test.expectHash, got.InclusionProof.RootHash)
			assert.Equal(t, test.expectBody, got.CanonicalizedBody)
		})
	}
}

func TestReadTile(t *testing.T) {
	ctx := context.Background()
	tileHash := hexDecodeOrDie(t, "81bfc09c412c04da53a1b0ddb94dce48d6a24e9ea58987f7d45a04e8007fb3ca")
	s := storage{
		readTileFn: func(_ context.Context, level, index uint64, _ uint8) ([]byte, error) {
			if level != 0 && index != 1 {
				return nil, fmt.Errorf("not found")
			}
			return tileHash, nil
		},
	}
	tests := []struct {
		name       string
		level      uint64
		index      uint64
		p          uint8
		expectHash []byte
		expectErr  error
	}{
		{
			name:       "tile exists",
			level:      0,
			index:      1,
			p:          0,
			expectHash: tileHash,
		},
		{
			name:      "tile doesn't exist",
			level:     1,
			index:     2,
			p:         0,
			expectErr: fmt.Errorf("reading tile level 1 index 2 p 0: not found"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := s.ReadTile(ctx, test.level, test.index, test.p)
			assert.Equal(t, test.expectHash, got)
			if test.expectErr != nil {
				assert.ErrorContains(t, gotErr, test.expectErr.Error())
			} else {
				assert.NoError(t, gotErr)
			}
		})
	}
}

func TestAppendOptions(t *testing.T) {
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}
	ao, err := NewAppendOptions(context.Background(), "test", sv)
	assert.NoError(t, err)
	ao = WithLifecycleOptions(ao, 42, 42*time.Millisecond, 42*time.Second, 42)
	assert.Equal(t, uint(42), ao.BatchMaxSize())
	assert.Equal(t, 42*time.Millisecond, ao.BatchMaxAge())
	assert.Equal(t, 42*time.Second, ao.CheckpointInterval())
	assert.Equal(t, uint(42), ao.PushbackMaxOutstanding())
	ao = WithAntispamOptions(ao, nil) // initializes non-persistent antispam
	examplePolicy := `witness o1 transparency.dev/DEV:witness-little-garden+4b7fca75+AStusOxINQNUTN5Oj8HObRkh2yHf/MwYaGX4CPdiVEPM https://api.transparency.dev/dev/witness/little-garden 
quorum o1`
	_, err = WithWitnessing(ao, []byte(examplePolicy))
	assert.NoError(t, err)
}

func TestNewDriver(t *testing.T) {
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
			errContains: "no flags provided to initialize Tessera driver",
		},
		{
			name: "GCP configuration incomplete - missing Spanner",
			config: DriverConfiguration{
				Hostname:  "test",
				GCPBucket: "test-bucket",
			},
			expectErr:   true,
			errContains: "no flags provided to initialize Tessera driver",
		},
		{
			name: "GCP configuration incomplete - missing bucket",
			config: DriverConfiguration{
				Hostname:     "test",
				GCPSpannerDB: "projects/test/instances/test/databases/test",
			},
			expectErr:   true,
			errContains: "no flags provided to initialize Tessera driver",
		},
		{
			name: "AWS configuration incomplete - missing MySQL DSN",
			config: DriverConfiguration{
				Hostname:  "test",
				AWSBucket: "test-bucket",
			},
			expectErr:   true,
			errContains: "no flags provided to initialize Tessera driver",
		},
		{
			name: "AWS configuration incomplete - missing bucket",
			config: DriverConfiguration{
				Hostname:    "test",
				AWSMySQLDSN: "user:pass@tcp(localhost:3306)/db",
			},
			expectErr:   true,
			errContains: "no flags provided to initialize Tessera driver",
		},
		{
			name: "GCP configuration complete",
			config: DriverConfiguration{
				Hostname:     "test",
				GCPBucket:    "test-bucket",
				GCPSpannerDB: "projects/test/instances/test/databases/test",
			},
			skipReason: "requires GCP credentials and connectivity",
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
				// antispam may be nil if PersistentAntispam is false
			}
		})
	}
}

func hexDecodeOrDie(t *testing.T, text string) []byte {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

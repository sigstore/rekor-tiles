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
	tessera "github.com/transparency-dev/trillian-tessera"
)

var tileHash = "81bfc09c412c04da53a1b0ddb94dce48d6a24e9ea58987f7d45a04e8007fb3ca"

func TestAdd(t *testing.T) {
	ctx := context.Background()
	readCheckpoint := func(_ context.Context) ([]byte, error) {
		<-time.After(5 * time.Millisecond)
		return []byte(`test.origin
1
gb/AnEEsBNpTobDduU3OSNaiTp6liYf31FoE6AB/s8o=

— test.origin AAAAAW5vb3AKMQpnYi9BbkVFc0JOcFRvYkRkdVUzT1NOYWlUcDZsaVlmMzFGb0U2QUIvczhvPQo=`), nil
	}
	s := storage{
		awaiter: tessera.NewIntegrationAwaiter(ctx, readCheckpoint, 10*time.Millisecond),
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return hex.DecodeString(tileHash)
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
			expectHash:     []byte(tileHash),
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
	decodedTileHash, err := hex.DecodeString(tileHash)
	if err != nil {
		t.Fatal(err)
	}
	s := storage{
		readTileFn: func(_ context.Context, level, index uint64, _ uint8) ([]byte, error) {
			if level != 0 && index != 1 {
				return nil, fmt.Errorf("not found")
			}
			return decodedTileHash, nil
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
			expectHash: decodedTileHash,
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
	_, err = WithAntispamOptions(context.Background(), ao, false, 100, 1000, "spannerdb")
	assert.NoError(t, err)
}

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
	"github.com/stretchr/testify/require"
	logformat "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
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

func TestAddOrGet(t *testing.T) {
	ctx := context.Background()
	entry := tessera.NewEntry([]byte("stuff"))
	leafHash := entry.LeafHash()
	otherLeaf := tessera.NewEntry([]byte("other")).LeafHash()
	thirdLeaf := tessera.NewEntry([]byte("third")).LeafHash()
	rootSize2 := rfc6962.DefaultHasher.HashChildren(leafHash, otherLeaf)
	rootSize3 := rfc6962.DefaultHasher.HashChildren(rootSize2, thirdLeaf)

	cpSize1 := append(logformat.Checkpoint{Origin: "test.origin", Size: 1, Hash: leafHash}.Marshal(), []byte("\n— test.origin AAAA\n")...)
	cpSize2 := append(logformat.Checkpoint{Origin: "test.origin", Size: 2, Hash: rootSize2}.Marshal(), []byte("\n— test.origin AAAA\n")...)
	cpSize3 := append(logformat.Checkpoint{Origin: "test.origin", Size: 3, Hash: rootSize3}.Marshal(), []byte("\n— test.origin AAAA\n")...)

	tests := []struct {
		name                   string
		initialCP              []byte
		addFn                  func(context.Context, *tessera.Entry) tessera.IndexFuture
		readTileFn             func(context.Context, uint64, uint64, uint8) ([]byte, error)
		readCheckpointFn       func(context.Context) ([]byte, error)
		cancelOnTileRead       bool
		expectDup              bool
		expectTreeSize         int64
		expectHash             []byte
		expectHashes           [][]byte
		expectCheckpoint       []byte
		expectErr              string
		expectVerifyErr        bool
		expectCheckpointCalled bool
		expectTileCalls        int
	}{
		{
			name:      "new entry",
			initialCP: cpSize1,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return leafHash, nil
			},
			expectDup:        false,
			expectTreeSize:   1,
			expectHash:       leafHash,
			expectHashes:     [][]byte{},
			expectCheckpoint: cpSize1,
		},
		{
			name:      "duplicate entry returns proof",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return append(append([]byte{}, leafHash...), otherLeaf...), nil
			},
			expectDup:        true,
			expectTreeSize:   2,
			expectHash:       rootSize2,
			expectHashes:     [][]byte{otherLeaf},
			expectCheckpoint: cpSize2,
			expectTileCalls:  1,
		},
		{
			name:      "duplicate inclusion proof verification failure does not retry",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return append(append([]byte{}, thirdLeaf...), thirdLeaf...), nil
			},
			// TODO: Remove readCheckpointFn/expectCheckpointCalled once the tessera@v1.0.4 retry workaround is removed.
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize3, nil
			},
			expectErr:              "verifying inclusion proof",
			expectVerifyErr:        true,
			expectCheckpointCalled: false,
			expectTileCalls:        1,
		},
		{
			name:      "integration failed",
			initialCP: cpSize1,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{}, fmt.Errorf("server error") }
			},
			expectErr: "add entry: await: server error",
		},
		// TODO: The cases below are temporary tests for the stale-checkpoint retry workaround
		// in storage.add (needed until we upgrade past tessera@v1.0.4 to pick up
		// transparency-dev/tessera#1260 and #1241). Remove them when removing the retry.
		{
			name:      "duplicate retries with fresh checkpoint on stale partial tile",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, p uint8) ([]byte, error) {
				if p == 2 {
					return nil, fmt.Errorf("storage: object doesn't exist")
				}
				return append(append(append([]byte{}, leafHash...), otherLeaf...), thirdLeaf...), nil
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize3, nil
			},
			expectDup:              true,
			expectTreeSize:         3,
			expectHash:             rootSize3,
			expectHashes:           [][]byte{otherLeaf, thirdLeaf},
			expectCheckpoint:       cpSize3,
			expectCheckpointCalled: true,
			expectTileCalls:        2,
		},
		{
			name:      "duplicate tile read failure with checkpoint error preserves original error",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return nil, fmt.Errorf("tile unavailable")
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return nil, fmt.Errorf("checkpoint unavailable")
			},
			expectErr:              "tile unavailable",
			expectCheckpointCalled: true,
			expectTileCalls:        1,
		},
		{
			name:      "duplicate unchanged checkpoint skips second proof build",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return nil, fmt.Errorf("tile unavailable")
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize2, nil
			},
			expectErr:              "tile unavailable",
			expectCheckpointCalled: true,
			expectTileCalls:        1,
		},
		{
			name:      "duplicate retry failure surfaces retry error",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, p uint8) ([]byte, error) {
				if p == 2 {
					return nil, fmt.Errorf("first failure")
				}
				return nil, fmt.Errorf("retry failure")
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize3, nil
			},
			expectErr:              "retry failure",
			expectCheckpointCalled: true,
			expectTileCalls:        2,
		},
		{
			name:      "duplicate canceled context does not retry",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: true}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return nil, context.Canceled
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize3, nil
			},
			cancelOnTileRead:       true,
			expectErr:              "context canceled",
			expectCheckpointCalled: false,
			expectTileCalls:        1,
		},
		{
			name:      "non-duplicate tile read failure does not retry",
			initialCP: cpSize2,
			addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
				return func() (tessera.Index, error) { return tessera.Index{Index: 0, IsDup: false}, nil }
			},
			readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
				return nil, fmt.Errorf("tile unavailable")
			},
			readCheckpointFn: func(_ context.Context) ([]byte, error) {
				return cpSize3, nil
			},
			expectErr:              "tile unavailable",
			expectCheckpointCalled: false,
			expectTileCalls:        1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			var readTileCalls int
			readTileFn := test.readTileFn
			if readTileFn != nil {
				orig := readTileFn
				readTileFn = func(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
					readTileCalls++
					if test.cancelOnTileRead {
						cancel()
					}
					return orig(ctx, l, i, p)
				}
			}
			var readCheckpointCalled bool
			readCheckpointFn := test.readCheckpointFn
			if readCheckpointFn != nil {
				orig := readCheckpointFn
				readCheckpointFn = func(ctx context.Context) ([]byte, error) {
					readCheckpointCalled = true
					return orig(ctx)
				}
			}
			s := storage{
				awaiter: tessera.NewPublicationAwaiter(testCtx, func(_ context.Context) ([]byte, error) {
					return test.initialCP, nil
				}, 5*time.Millisecond),
				addFn:            test.addFn,
				readTileFn:       readTileFn,
				readCheckpointFn: readCheckpointFn,
			}
			got, gotDup, gotErr := s.AddOrGet(testCtx, entry)
			if test.readCheckpointFn != nil {
				assert.Equal(t, test.expectCheckpointCalled, readCheckpointCalled)
			}
			if test.expectTileCalls > 0 {
				assert.Equal(t, test.expectTileCalls, readTileCalls)
			}
			if test.expectErr != "" {
				require.ErrorContains(t, gotErr, test.expectErr)
				assert.Nil(t, got)
				assert.False(t, gotDup)
				if test.expectVerifyErr {
					var verifyErr InclusionProofVerificationError
					assert.ErrorAs(t, gotErr, &verifyErr)
				}
				return
			}
			require.NoError(t, gotErr)
			assert.Equal(t, test.expectDup, gotDup)
			assert.Equal(t, int64(0), got.LogIndex)
			assert.Equal(t, test.expectTreeSize, got.InclusionProof.TreeSize)
			assert.Equal(t, test.expectHash, got.InclusionProof.RootHash)
			assert.Equal(t, test.expectHashes, got.InclusionProof.Hashes)
			assert.Equal(t, string(test.expectCheckpoint), got.InclusionProof.Checkpoint.Envelope)
			assert.Equal(t, entry.Data(), got.CanonicalizedBody)
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
	examplePolicy := `witness o1 transparency.dev/DEV:witness-little-garden+d8042a87+BCtusOxINQNUTN5Oj8HObRkh2yHf/MwYaGX4CPdiVEPM https://api.transparency.dev/dev/witness/little-garden 
quorum o1`
	_, err = WithWitnessing(ao, []byte(examplePolicy))
	assert.NoError(t, err)
}

func hexDecodeOrDie(t *testing.T, text string) []byte {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

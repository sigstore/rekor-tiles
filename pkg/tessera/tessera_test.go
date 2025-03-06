/*
Copyright 2025 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tessera

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

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
	s := Storage{
		awaiter: tessera.NewIntegrationAwaiter(ctx, readCheckpoint, 10*time.Millisecond),
		addFn: func(_ context.Context, _ *tessera.Entry) tessera.IndexFuture {
			return func() (uint64, error) { return 0, nil }
		},
		readTileFn: func(_ context.Context, _, _ uint64, _ uint8) ([]byte, error) {
			return hex.DecodeString(tileHash)
		},
	}
	entry := tessera.NewEntry([]byte("stuff"))
	got, gotErr := s.Add(ctx, entry)
	assert.NoError(t, gotErr)
	assert.Equal(t, int64(0), got.LogIndex)
	assert.Equal(t, int64(1), got.InclusionProof.TreeSize)
	assert.Equal(t, []byte(tileHash), got.InclusionProof.RootHash)
}

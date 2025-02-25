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
	"time"

	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	logformat "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/client"
)

// Storage provides the functions to add entries to a Tessera log.
type Storage struct {
	origin     string
	awaiter    *tessera.IntegrationAwaiter
	addFn      tessera.AddFn
	readTileFn client.TileFetcherFunc
}

// NewStorage creates a Tessera storage object for the provided driver and signer.
func NewStorage(ctx context.Context, origin string, driver tessera.Driver, signer signature.Signer) (*Storage, error) {
	noteSigner, err := note.NewNoteSigner(ctx, origin, signer)
	if err != nil {
		return nil, fmt.Errorf("getting note signer: %w", err)
	}
	appender, reader, err := tessera.NewAppender(ctx, driver,
		tessera.NewAppendOptions().WithCheckpointSigner(noteSigner),
	)
	if err != nil {
		return nil, fmt.Errorf("getting tessera appender: %w", err)
	}
	awaiter := tessera.NewIntegrationAwaiter(ctx, reader.ReadCheckpoint, 1*time.Second)
	return &Storage{
		origin:     origin,
		awaiter:    awaiter,
		addFn:      appender.Add,
		readTileFn: reader.ReadTile,
	}, nil
}

// Add adds a Tessera entry to the log, waits for it to be sequenced into the log,
// and returns the log index and inclusion proof as a TransparencyLogEntry object.
func (s *Storage) Add(ctx context.Context, entry *tessera.Entry) (*rekor_pb.TransparencyLogEntry, error) {
	idx, checkpointBody, err := s.addEntry(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("add entry: %w", err)
	}
	inclusionProof, err := s.buildProof(ctx, idx, checkpointBody, entry.LeafHash())
	if err != nil {
		return nil, fmt.Errorf("building inclusion proof: %w", err)
	}
	return &rekor_pb.TransparencyLogEntry{
		LogIndex:       idx.i,
		InclusionProof: inclusionProof,
	}, nil
}

// ReadTile looks up the tile at the given level, index within the level, and
// width of the tile if partial, and returns the raw bytes of the tile.
func (s *Storage) ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	tile, err := s.readTileFn(ctx, level, index, p)
	if err != nil {
		return nil, fmt.Errorf("reading tile level %d index %d p %d: %w", level, index, p, err)
	}
	return tile, nil
}

func (s *Storage) addEntry(ctx context.Context, entry *tessera.Entry) (*safeInt64, []byte, error) {
	idx, checkpointBody, err := s.awaiter.Await(ctx, s.addFn(ctx, entry))
	if err != nil {
		return nil, nil, fmt.Errorf("await: %w", err)
	}
	safeIdx, err := newSafeInt64(idx)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid index: %w", err)
	}
	return safeIdx, checkpointBody, nil
}

func (s *Storage) buildProof(ctx context.Context, idx *safeInt64, signedCheckpoint, leafHash []byte) (*rekor_pb.InclusionProof, error) {
	checkpoint, err := unmarshalCheckpoint(signedCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling checkpoint: %w", err)
	}
	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint, s.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("new proof builder: %w", err)
	}
	inclusionProof, err := proofBuilder.InclusionProof(ctx, idx.u)
	if err != nil {
		return nil, fmt.Errorf("generating inclusion proof: %w", err)
	}
	safeCheckpointSize, err := newSafeInt64(checkpoint.Size)
	if err != nil {
		return nil, fmt.Errorf("invalid tree size: %d", checkpoint.Size)
	}
	// TODO(cmurphy): add metrics to detect when this inclusion proof ever fails as well as the overhead time for running this check.
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx.u, safeCheckpointSize.u, leafHash, inclusionProof, checkpoint.Hash); err != nil {
		return nil, fmt.Errorf("failed to verify entry inclusion: %w", err)
	}
	return &rekor_pb.InclusionProof{
		LogIndex: idx.i,
		RootHash: []byte(hex.EncodeToString(checkpoint.Hash)),
		TreeSize: safeCheckpointSize.i,
		Hashes:   inclusionProof,
		Checkpoint: &rekor_pb.Checkpoint{
			Envelope: string(signedCheckpoint),
		},
	}, nil
}

func unmarshalCheckpoint(checkpointBody []byte) (logformat.Checkpoint, error) {
	checkpoint := logformat.Checkpoint{}
	_, err := checkpoint.Unmarshal(checkpointBody)
	return checkpoint, err
}

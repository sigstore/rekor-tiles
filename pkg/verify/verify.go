//
// Copyright 2022 The Sigstore Authors.
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

package verify

import (
	"context"
	"crypto/sha256"
	"fmt"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func VerifyInclusionProof(entry *pbs.TransparencyLogEntry, cp *f_log.Checkpoint) error {
	leafHash := sha256.Sum256(entry.CanonicalizedBody)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(entry.LogIndex), cp.Size, leafHash[:], entry.InclusionProof.Hashes, cp.Hash); err != nil {
		return err
	}
	return nil
}

func VerifyCheckpoint(ctx context.Context, entry *pbs.TransparencyLogEntry, origin string, verifier signature.Verifier) (*f_log.Checkpoint, error) {
	v, err := note.NewNoteVerifier(ctx, origin, verifier)
	if err != nil {
		return nil, fmt.Errorf("error creating note verifier: %v", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint([]byte(entry.InclusionProof.GetCheckpoint().GetEnvelope()), v.Name(), v)
	if err != nil {
		return nil, fmt.Errorf("unverified checkpoint signature: %v", err)
	}
	return cp, nil
}

func VerifyLogEntry(ctx context.Context, entry *pbs.TransparencyLogEntry, origin string, verifier signature.Verifier) error {
	cp, err := VerifyCheckpoint(ctx, entry, origin, verifier)
	if err != nil {
		return err
	}
	if err := VerifyInclusionProof(entry, cp); err != nil {
		return nil
	}
	return nil
}

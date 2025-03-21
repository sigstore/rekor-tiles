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

package verify

import (
	"crypto/sha256"
	"fmt"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/rekor-tiles/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/signature"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// VerifyInclusionProof verifies an entry's inclusion proof
func VerifyInclusionProof(entry *pbs.TransparencyLogEntry, cp *f_log.Checkpoint) error { //nolint: revive
	leafHash := sha256.Sum256(entry.CanonicalizedBody)
	index, err := tessera.NewSafeInt64(entry.LogIndex)
	if err != nil {
		return fmt.Errorf("invalid index: %w", err)
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index.U(), cp.Size, leafHash[:], entry.InclusionProof.Hashes, cp.Hash); err != nil {
		return fmt.Errorf("verifying inclusion: %w", err)
	}
	return nil
}

// VerifyCheckpoint verifies the signature on the entry's inclusion proof checkpoint
func VerifyCheckpoint(entry *pbs.TransparencyLogEntry, origin string, verifier signature.Verifier) (*f_log.Checkpoint, error) { //nolint: revive
	v, err := note.NewNoteVerifier(origin, verifier)
	if err != nil {
		return nil, fmt.Errorf("error creating note verifier: %v", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint([]byte(entry.InclusionProof.GetCheckpoint().GetEnvelope()), v.Name(), v)
	if err != nil {
		return nil, fmt.Errorf("unverified checkpoint signature: %v", err)
	}
	return cp, nil
}

// VerifyLogEntry verifies the log entry: This includes verifying the signature on the entry's
// inclusion proof checkpoint and verifying the entry inclusion proof
func VerifyLogEntry(entry *pbs.TransparencyLogEntry, origin string, verifier signature.Verifier) error { //nolint: revive
	cp, err := VerifyCheckpoint(entry, origin, verifier)
	if err != nil {
		return err
	}
	return VerifyInclusionProof(entry, cp)
}

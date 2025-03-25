// Copyright 2025 The Sigstore Authors
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

package dsse

import (
	"crypto/sha256"
	"fmt"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
)

func ToLogEntryV0_0_2(ds *pb.DSSERequestV0_0_2) (*pb.DSSELogEntryV0_0_2, error) {
	if ds.Envelope == nil {
		return nil, fmt.Errorf("missing envelope")
	}
	if len(ds.Signatures) == 0 {
		return nil, fmt.Errorf("missing signatures")
	}
	if len(ds.Signatures) != len(ds.Envelope.Signatures) {
		return nil, fmt.Errorf("provided signatures do not match envelope signatures")
		// TODO(#10): check that the signatures and verifiers provided are a 1:1 match to the envelope signatures
	}
	for _, v := range ds.Signatures {
		if len(v.Signature) == 0 {
			return nil, fmt.Errorf("missing signatures")
		}
		if v.Verifier == nil {
			return nil, fmt.Errorf("missing verifier")
		}
		if err := verifier.Validate(v.Verifier); err != nil {
			return nil, err
		}
	}

	if ds.Envelope.Payload == nil {
		return nil, fmt.Errorf("missing envelope payload")
	}
	payloadHash := sha256.Sum256([]byte(ds.Envelope.Payload))

	// TODO (#10): check that signatures can be validated against the provided keys

	if len(ds.Envelope.Signatures) == 0 {
		return nil, fmt.Errorf("missing envelope signatures")
	}

	return &pb.DSSELogEntryV0_0_2{
		PayloadHash: &v1.HashOutput{
			Algorithm: v1.HashAlgorithm_SHA2_256,
			Digest:    payloadHash[:],
		},
		Signatures: ds.Signatures,
	}, nil
}

// Copyright 2026 The Sigstore Authors
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

package hashedrekord

import (
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	sigsignature "github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/protobuf/encoding/protojson"
)

// ReconstructLeafHash builds a HashedRekordLogEntryV002 from the supplied
// inputs and applies the same protojson.Marshal -> jsoncanonicalizer.Transform
// -> RFC 6962 HashLeaf pipeline the log service uses when integrating an entry.
// The result is the leaf hash a Verifier can use as the input to an inclusion
// proof, implementing the spec's preferred "Recompute the leaf" path
// (rekor-v2-spec §6.1.4).
//
// HashOutput.Algorithm is derived from signature.Verifier.KeyDetails via the
// Algorithm Registry, matching the server's canonicalization. Callers MUST
// supply the bundle's digest and *pb.Signature directly; the verifier oneof
// (X509Certificate vs PublicKey) inside signature.Verifier must match the
// bundle's verification material.
func ReconstructLeafHash(digest []byte, signature *pb.Signature) ([]byte, error) {
	algDetails, err := sigsignature.GetAlgorithmDetails(signature.GetVerifier().GetKeyDetails())
	if err != nil {
		return nil, fmt.Errorf("getting key algorithm details: %w", err)
	}
	entry := &pb.Entry{
		Kind:       "hashedrekord",
		ApiVersion: "0.0.2",
		Spec: &pb.Spec{
			Spec: &pb.Spec_HashedRekordV002{
				HashedRekordV002: &pb.HashedRekordLogEntryV002{
					Data:      &v1.HashOutput{Digest: digest, Algorithm: algDetails.GetProtoHashType()},
					Signature: signature,
				},
			},
		},
	}
	serialized, err := protojson.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshaling reconstructed entry: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(serialized)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing reconstructed entry: %w", err)
	}
	return rfc6962.DefaultHasher.HashLeaf(canonicalized), nil
}

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

package hashedrekord

import (
	"fmt"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
)

func ToLogEntryV0_0_2(hr *pb.HashedRekordRequestV0_0_2) (*pb.HashedRekordLogEntryV0_0_2, error) {
	if hr.Signature == nil || len(hr.Signature.Signature) == 0 {
		return nil, fmt.Errorf("missing signature")
	}
	if hr.Signature.Verifier == nil {
		return nil, fmt.Errorf("missing verifier")
	}
	if hr.Data == nil {
		return nil, fmt.Errorf("missing data")
	}
	if len(hr.Data.Digest) == 0 {
		return nil, fmt.Errorf("missing data digest")
	}
	if err := verifier.Validate(hr.Signature.Verifier); err != nil {
		return nil, err
	}

	// TODO(#10): check if signatures can be validated

	return &pb.HashedRekordLogEntryV0_0_2{
		Signature: hr.Signature,
		Data:      hr.Data,
	}, nil
}

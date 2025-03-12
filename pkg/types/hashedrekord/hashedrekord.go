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

func Validate(hr *pb.HashedRekordRequest) error {
	if len(hr.Signature) == 0 {
		return fmt.Errorf("missing signature")
	}
	if hr.Verifier == nil {
		return fmt.Errorf("missing verifier")
	}
	if hr.Data == nil {
		return fmt.Errorf("missing data")
	}
	if len(hr.Data.Digest) == 0 {
		return fmt.Errorf("missing data digest")
	}
	return verifier.Validate(hr.Verifier)
}

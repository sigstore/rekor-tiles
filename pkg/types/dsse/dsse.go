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
	"fmt"

	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
)

func Validate(ds *pb.DSSERequest) error {
	if ds.Envelope == "" {
		return fmt.Errorf("missing envelope")
	}
	if len(ds.Verifier) == 0 {
		return fmt.Errorf("missing verifiers")
	}
	for _, v := range ds.Verifier {
		if err := verifier.Validate(v); err != nil {
			return err
		}
	}
	return nil
}

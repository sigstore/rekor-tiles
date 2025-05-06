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

package types

import (
	"fmt"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
)

// GetKindVersion returns the entry kind and version for a given create request.
func GetKindVersion(req *pb.CreateEntryRequest) (*pbs.KindVersion, error) {
	switch req.GetSpec().(type) {
	case *pb.CreateEntryRequest_HashedRekordRequestV0_0_2:
		return &pbs.KindVersion{Kind: "hashedrekord", Version: "0.0.2"}, nil
	case *pb.CreateEntryRequest_DsseRequestV0_0_2:
		return &pbs.KindVersion{Kind: "dsse", Version: "0.0.2"}, nil
	default:
		// should not happen
		return nil, fmt.Errorf("invalid type, request must be for hashedrekord or dsse")
	}
}

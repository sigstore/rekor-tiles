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
	"reflect"
	"testing"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
)

func TestGetKindVersion(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.CreateEntryRequest
		expectedKind  *pbs.KindVersion
		expectedError string
	}{
		{
			name: "HashedRekordRequestV0_0_2",
			request: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_HashedRekordRequestV0_0_2{},
			},
			expectedKind: &pbs.KindVersion{Kind: "hashedrekord", Version: "0.0.2"},
		},
		{
			name: "DsseRequestV0_0_2",
			request: &pb.CreateEntryRequest{
				Spec: &pb.CreateEntryRequest_DsseRequestV0_0_2{},
			},
			expectedKind: &pbs.KindVersion{Kind: "dsse", Version: "0.0.2"},
		},
		{
			name: "Invalid type",
			request: &pb.CreateEntryRequest{
				Spec: nil,
			},
			expectedKind:  nil,
			expectedError: "invalid type, request must be for hashedrekord or dsse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kindVersion, err := GetKindVersion(tc.request)
			if tc.expectedError != "" {
				if err == nil {
					t.Errorf("expected error '%s', but got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError {
					t.Errorf("expected error '%s', but got '%s'", tc.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got '%s'", err.Error())
				}
			}
			if !reflect.DeepEqual(tc.expectedKind, kindVersion) {
				t.Errorf("expected kind version %v, but got %v", tc.expectedKind, kindVersion)
			}
		})
	}
}

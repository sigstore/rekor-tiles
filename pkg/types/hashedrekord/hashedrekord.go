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
	"bytes"
	"crypto"
	"fmt"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/pki/x509"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// ToLogEntry validates a request and converts it to a log entry type for inclusion in the log
// TODO(#178) separate out ToLogEntry into proto validation, cyrpto validation and log entry conversion
func ToLogEntry(hr *pb.HashedRekordRequestV0_0_2) (*pb.HashedRekordLogEntryV0_0_2, error) {
	if hr.Signature == nil || len(hr.Signature.Content) == 0 {
		return nil, fmt.Errorf("missing signature")
	}
	if hr.Signature.Verifier == nil {
		return nil, fmt.Errorf("missing verifier")
	}
	if len(hr.Digest) == 0 {
		return nil, fmt.Errorf("missing digest")
	}
	if err := verifier.Validate(hr.Signature.Verifier); err != nil {
		return nil, err
	}
	sigObj, err := x509.NewSignatureWithOpts(bytes.NewReader(hr.Signature.Content), options.WithED25519ph())
	if err != nil {
		return nil, fmt.Errorf("parsing signature: %w", err)
	}
	var keyObj *x509.PublicKey
	if pubKey := hr.Signature.Verifier.GetPublicKey(); pubKey != nil {
		keyObj, err = x509.NewPublicKey(bytes.NewReader(pubKey.RawBytes))
	} else if cert := hr.Signature.Verifier.GetX509Certificate(); cert != nil {
		keyObj, err = x509.NewPublicKey(bytes.NewReader(cert.RawBytes))
	} else {
		return nil, fmt.Errorf("must contain either a public key or X.509 certificate")
	}
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	// TODO: Look up hash with sigstore/sigstore's GetAlgorithmDetails(hr.Signature.Verifier.KeyDetails).GetHashType()
	// Update hardcoded SHA256 during signature verification and as output

	if err := sigObj.Verify(nil, keyObj, options.WithDigest(hr.Digest), options.WithCryptoSignerOpts(crypto.SHA256)); err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}

	return &pb.HashedRekordLogEntryV0_0_2{
		Signature: hr.Signature,
		Data:      &v1.HashOutput{Digest: hr.Digest, Algorithm: v1.HashAlgorithm_SHA2_256},
	}, nil
}

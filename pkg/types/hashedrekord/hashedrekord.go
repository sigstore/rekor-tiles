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
	if hr.Data.Digest == nil {
		return fmt.Errorf("missing data digest")
	}
	if err := verifier.Validate(hr.Verifier); err != nil {
		return err
	}
	sigObj, err := x509.NewSignatureWithOpts(bytes.NewReader(hr.Signature), options.WithED25519ph())
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}
	var keyObj *x509.PublicKey
	if pubKey := hr.Verifier.GetPublicKey(); pubKey != nil {
		keyObj, err = x509.NewPublicKey(bytes.NewReader(pubKey.RawBytes))
	} else if cert := hr.Verifier.GetX509Certificate(); cert != nil {
		keyObj, err = x509.NewPublicKey(bytes.NewReader(cert.RawBytes))
	} else {
		return fmt.Errorf("must contain either a public key or X.509 certificate")
	}
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}
	var alg crypto.Hash
	switch hr.Data.Algorithm {
	case v1.HashAlgorithm_SHA2_384:
		alg = crypto.SHA384
	case v1.HashAlgorithm_SHA2_512:
		alg = crypto.SHA512
	default:
		alg = crypto.SHA256
	}
	if err := sigObj.Verify(nil, keyObj, options.WithDigest(hr.Data.Digest), options.WithCryptoSignerOpts(alg)); err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}

	return nil
}

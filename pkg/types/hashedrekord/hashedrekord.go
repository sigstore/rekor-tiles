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
	"fmt"
	"reflect"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor-tiles/pkg/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/types/validator"
	"github.com/sigstore/rekor-tiles/pkg/verifier"
	"github.com/sigstore/rekor-tiles/pkg/verifier/certificate"
	"github.com/sigstore/rekor-tiles/pkg/verifier/publickey"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// ToLogEntry validates a request and converts it to a log entry type for inclusion in the log
// TODO(#178) separate out ToLogEntry into proto validation, cyrpto validation and log entry conversion
func ToLogEntry(hr *pb.HashedRekordRequestV0_0_2, algorithmRegistry *signature.AlgorithmRegistryConfig) (*pb.HashedRekordLogEntryV0_0_2, error) {
	if hr.Signature == nil || len(hr.Signature.Content) == 0 {
		return nil, fmt.Errorf("missing signature")
	}
	if hr.Signature.Verifier == nil {
		return nil, fmt.Errorf("missing verifier")
	}
	if len(hr.Digest) == 0 {
		return nil, fmt.Errorf("missing digest")
	}
	if err := validator.Validate(hr.Signature.Verifier); err != nil {
		return nil, err
	}

	var v verifier.Verifier
	var err error
	if pubKey := hr.Signature.Verifier.GetPublicKey(); pubKey != nil {
		v, err = publickey.NewVerifier(bytes.NewReader(pubKey.RawBytes))
	} else if cert := hr.Signature.Verifier.GetX509Certificate(); cert != nil {
		v, err = certificate.NewVerifier(bytes.NewReader(cert.RawBytes))
	} else {
		return nil, fmt.Errorf("must contain either a public key or X.509 certificate")
	}
	if err != nil {
		return nil, fmt.Errorf("parsing verifier: %w", err)
	}

	algDetails, err := signature.GetAlgorithmDetails(hr.Signature.Verifier.KeyDetails)
	if err != nil {
		return nil, fmt.Errorf("getting key algorithm details: %w", err)
	}
	alg := algDetails.GetHashType()

	valid, err := algorithmregistry.CheckEntryAlgorithms(v.PublicKey(), alg, algorithmRegistry)
	if err != nil {
		return nil, fmt.Errorf("checking entry algorithm: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("unsupported entry algorithm for key %s, digest %s", reflect.TypeOf(v.PublicKey()), alg.String())
	}

	sigVerifier, err := signature.LoadVerifierWithOpts(v.PublicKey(), options.WithED25519ph())
	if err != nil {
		return nil, fmt.Errorf("loading verifier: %v", err)
	}
	if err := sigVerifier.VerifySignature(
		bytes.NewReader(hr.Signature.Content), nil, options.WithDigest(hr.Digest), options.WithCryptoSignerOpts(alg)); err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}

	return &pb.HashedRekordLogEntryV0_0_2{
		Signature: hr.Signature,
		// TODO: Remove hardcoded algorithm
		Data: &v1.HashOutput{Digest: hr.Digest, Algorithm: v1.HashAlgorithm_SHA2_256},
	}, nil
}

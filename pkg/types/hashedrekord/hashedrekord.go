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
	"github.com/sigstore/rekor-tiles/internal/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	pbverifier "github.com/sigstore/rekor-tiles/pkg/types/verifier"
	"github.com/sigstore/rekor-tiles/pkg/verifier"
	"github.com/sigstore/rekor-tiles/pkg/verifier/certificate"
	"github.com/sigstore/rekor-tiles/pkg/verifier/publickey"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// ToLogEntry validates a request, verifies its signature, and converts it to a log entry type for inclusion in the log
func ToLogEntry(hr *pb.HashedRekordRequestV002, algorithmRegistry *signature.AlgorithmRegistryConfig) (*pb.Entry, error) {
	if err := validate(hr); err != nil {
		return nil, err
	}

	v, err := extractVerifier(hr)
	if err != nil {
		return nil, err
	}

	algDetails, err := verifySupportedAlgorithm(hr.Signature.Verifier.KeyDetails, v, algorithmRegistry)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(hr, v, algDetails.GetHashType()); err != nil {
		return nil, err
	}

	return &pb.Entry{
		Kind:       "hashedrekord",
		ApiVersion: "0.0.2",
		Spec: &pb.Spec{
			Spec: &pb.Spec_HashedRekordV002{
				HashedRekordV002: &pb.HashedRekordLogEntryV002{
					Signature: hr.Signature,
					Data:      &v1.HashOutput{Digest: hr.Digest, Algorithm: algDetails.GetProtoHashType()},
				},
			},
		},
	}, nil
}

// validate validates there are no missing fields in a HashedRekordRequestV002 protobuf
func validate(hr *pb.HashedRekordRequestV002) error {
	if hr.Signature == nil || len(hr.Signature.Content) == 0 {
		return fmt.Errorf("missing signature")
	}
	if hr.Signature.Verifier == nil {
		return fmt.Errorf("missing verifier")
	}
	if len(hr.Digest) == 0 {
		return fmt.Errorf("missing digest")
	}
	if err := pbverifier.Validate(hr.Signature.Verifier); err != nil {
		return fmt.Errorf("invalid verifier: %v", err)
	}
	return nil
}

func extractVerifier(hr *pb.HashedRekordRequestV002) (verifier.Verifier, error) {
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
	return v, nil
}

// verifySupportedAlgorithm confirms that the signature and digest algorithm pair is supported by this server
// instance, and returns details about the signing algorithm to be used while verifying the entry signature.
func verifySupportedAlgorithm(keyDetails v1.PublicKeyDetails, v verifier.Verifier, algorithmRegistry *signature.AlgorithmRegistryConfig) (signature.AlgorithmDetails, error) {
	algDetails, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return signature.AlgorithmDetails{}, fmt.Errorf("getting key algorithm details: %w", err)
	}
	alg := algDetails.GetHashType()

	valid, err := algorithmregistry.CheckEntryAlgorithms(v.PublicKey(), alg, algorithmRegistry)
	if err != nil {
		return signature.AlgorithmDetails{}, fmt.Errorf("checking entry algorithm: %w", err)
	}
	if !valid {
		return signature.AlgorithmDetails{}, &algorithmregistry.UnsupportedAlgorithm{Pub: v.PublicKey(), Alg: alg}
	}
	return algDetails, nil
}

func verifySignature(hr *pb.HashedRekordRequestV002, v verifier.Verifier, hashAlg crypto.Hash) error {
	sigVerifier, err := signature.LoadVerifierWithOpts(v.PublicKey(), options.WithED25519ph())
	if err != nil {
		return fmt.Errorf("loading verifier: %v", err)
	}
	if err := sigVerifier.VerifySignature(
		bytes.NewReader(hr.Signature.Content), nil, options.WithDigest(hr.Digest), options.WithCryptoSignerOpts(hashAlg)); err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}
	return nil
}

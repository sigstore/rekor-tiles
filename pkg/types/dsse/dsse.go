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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	pbverifier "github.com/sigstore/rekor-tiles/v2/pkg/types/verifier"
	"github.com/sigstore/rekor-tiles/v2/pkg/verifier"
	"github.com/sigstore/rekor-tiles/v2/pkg/verifier/certificate"
	"github.com/sigstore/rekor-tiles/v2/pkg/verifier/publickey"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	maxVerifiers  = 10
	maxSignatures = 10
)

// ToLogEntry validates a request, verifies all envelope signatures, and converts it to a log entry type for inclusion in the log
func ToLogEntry(ds *pb.DSSERequestV002, algorithmRegistry *signature.AlgorithmRegistryConfig) (*pb.Entry, error) {
	if err := validate(ds); err != nil {
		return nil, err
	}

	verifiers, err := extractVerifiers(ds)
	if err != nil {
		return nil, err
	}

	signerVerifiers, err := verifyEnvelopeAndSupportedAlgs(verifiers, ds.Envelope, algorithmRegistry)
	if err != nil {
		return nil, err
	}

	// Canonicalize the order of the signatures. Signatures are sorted in ascending order by the stringified
	// representation of the raw (e.g. not base64-encoded) signature.
	var sortedSigs []string
	for sig := range signerVerifiers {
		sortedSigs = append(sortedSigs, sig)
	}
	slices.Sort(sortedSigs)
	var canonicalizedSigs []*pb.Signature
	for _, s := range sortedSigs {
		canonicalizedSigs = append(canonicalizedSigs, &pb.Signature{Content: []byte(s), Verifier: signerVerifiers[s]})
	}

	// Use a hardcoded SHA-256 hashing algorithm for the payload hash,
	// since each signature digest algorithm might be different. Clients
	// must not use the payload hash when verifying signatures.
	payloadHash := sha256.Sum256(ds.Envelope.Payload)

	return &pb.Entry{
		Kind:       "dsse",
		ApiVersion: "0.0.2",
		Spec: &pb.Spec{
			Spec: &pb.Spec_DsseV002{
				DsseV002: &pb.DSSELogEntryV002{
					PayloadHash: &v1.HashOutput{
						Algorithm: v1.HashAlgorithm_SHA2_256,
						Digest:    payloadHash[:],
					},
					Signatures: canonicalizedSigs,
				},
			},
		},
	}, nil
}

// validate validates there are no missing fields in a DSSERequestV002 protobuf
func validate(ds *pb.DSSERequestV002) error {
	if ds.Envelope == nil {
		return fmt.Errorf("missing envelope")
	}
	if len(ds.Verifiers) == 0 {
		return fmt.Errorf("missing verifiers")
	}
	if len(ds.Verifiers) > maxVerifiers {
		return fmt.Errorf("too many verifiers: %d, max allowed: %d", len(ds.Verifiers), maxVerifiers)
	}
	for _, v := range ds.Verifiers {
		if err := pbverifier.Validate(v); err != nil {
			return fmt.Errorf("invalid verifier: %v", err)
		}
	}
	if len(ds.Envelope.Signatures) == 0 {
		return fmt.Errorf("envelope missing signatures")
	}
	if len(ds.Envelope.Signatures) > maxSignatures {
		return fmt.Errorf("too many signatures: %d, max allowed: %d", len(ds.Envelope.Signatures), maxSignatures)
	}
	for _, s := range ds.Envelope.Signatures {
		if s == nil || len(s.Sig) == 0 {
			return fmt.Errorf("envelope signature empty")
		}
	}
	return nil
}

// extractVerifiers returns a map of protobuf verifiers to verifier interface
func extractVerifiers(ds *pb.DSSERequestV002) (map[*pb.Verifier]verifier.Verifier, error) {
	verifiers := make(map[*pb.Verifier]verifier.Verifier, 0)
	for _, v := range ds.Verifiers {
		pubKey := v.GetPublicKey()
		cert := v.GetX509Certificate()
		switch {
		case pubKey != nil:
			vf, err := publickey.NewVerifier(bytes.NewReader(pubKey.RawBytes))
			if err != nil {
				return nil, fmt.Errorf("parsing public key: %v", err)
			}
			verifiers[v] = vf
		case cert != nil:
			vf, err := certificate.NewVerifier(bytes.NewReader(cert.RawBytes))
			if err != nil {
				return nil, fmt.Errorf("parsing certificate: %v", err)
			}
			verifiers[v] = vf
		default:
			return nil, fmt.Errorf("must contain either a public key or X.509 certificate")
		}
	}
	return verifiers, nil
}

// verifyEnvelopeAndSupportedAlgs takes in verifiers, a map of key details to the signature verifier. Verifiers are used to
// to verify the envelope's signatures. Returns a map of signatures to their verifiers.
func verifyEnvelopeAndSupportedAlgs(verifiers map[*pb.Verifier]verifier.Verifier, pbenv *pbdsse.Envelope, algorithmRegistry *signature.AlgorithmRegistryConfig) (map[string]*pb.Verifier, error) {
	env := FromProto(pbenv)
	savs := make(map[string]*pb.Verifier, len(verifiers))
	// generate a fake id for these keys so we can get back to the key bytes and match them to their corresponding signature
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}

	for v, verifierKey := range verifiers {
		if len(allSigs) == 0 {
			break // if all signatures have been verified, do not attempt anymore
		}

		algDetails, err := signature.GetAlgorithmDetails(v.KeyDetails)
		if err != nil {
			return nil, fmt.Errorf("getting key algorithm details: %w", err)
		}
		alg := algDetails.GetHashType()

		// check if signing algorithm is supported by this Rekor instance
		valid, err := algorithmregistry.CheckEntryAlgorithms(verifierKey.PublicKey(), alg, algorithmRegistry)
		if err != nil {
			return nil, fmt.Errorf("checking entry algorithm: %w", err)
		}
		if !valid {
			return nil, &algorithmregistry.UnsupportedAlgorithm{Pub: verifierKey.PublicKey(), Alg: alg}
		}

		vfr, err := signature.LoadVerifier(verifierKey.PublicKey(), alg)
		if err != nil {
			return nil, fmt.Errorf("could not load verifier: %w", err)
		}

		dsseVfr, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{SignatureVerifier: vfr})
		if err != nil {
			return nil, fmt.Errorf("could not use public key as a dsse verifier: %w", err)
		}

		accepted, err := dsseVfr.Verify(context.Background(), env)
		if err != nil {
			return nil, fmt.Errorf("could not verify envelope: %w", err)
		}

		for _, accept := range accepted {
			delete(allSigs, accept.Sig.Sig)
			sigBytes, err := base64.StdEncoding.DecodeString(accept.Sig.Sig)
			if err != nil {
				// this should be unreachable
				return nil, fmt.Errorf("could not decode base64 signature: %w", err)
			}
			savs[string(sigBytes)] = v
		}
	}

	if len(allSigs) > 0 {
		return nil, errors.New("all signatures must have a key that verifies it")
	}

	return savs, nil
}

// FromProto converts a dsse proto message to a dsse struct
func FromProto(env *pbdsse.Envelope) *dsse.Envelope {
	var newEnv dsse.Envelope
	newEnv.PayloadType = env.PayloadType
	newEnv.Payload = base64.StdEncoding.EncodeToString(env.Payload)
	newEnv.Signatures = make([]dsse.Signature, 0, len(env.Signatures))
	for _, s := range env.Signatures {
		ns := dsse.Signature{
			KeyID: s.Keyid,
			Sig:   base64.StdEncoding.EncodeToString(s.Sig),
		}
		newEnv.Signatures = append(newEnv.Signatures, ns)
	}
	return &newEnv
}

// ToProto converts a dsse struct to a dsse proto message
func ToProto(env *dsse.Envelope) (*pbdsse.Envelope, error) {
	var newEnv pbdsse.Envelope
	newEnv.PayloadType = env.PayloadType
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode dsse payload: %w", err)
	}
	newEnv.Payload = payloadBytes
	newEnv.Signatures = make([]*pbdsse.Signature, 0, len(env.Signatures))
	for _, s := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return nil, fmt.Errorf("failed to decode dsse signature: %w", err)
		}
		ns := &pbdsse.Signature{
			Keyid: s.KeyID,
			Sig:   sigBytes,
		}
		newEnv.Signatures = append(newEnv.Signatures, ns)
	}
	return &newEnv, nil
}

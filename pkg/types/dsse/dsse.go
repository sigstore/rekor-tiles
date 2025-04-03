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
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	pbdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/pki/x509"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

func ToLogEntry(ds *pb.DSSERequestV0_0_2) (*pb.DSSELogEntryV0_0_2, error) {
	if ds.Envelope == nil {
		return nil, fmt.Errorf("missing envelope")
	}
	if len(ds.Verifiers) == 0 {
		return nil, fmt.Errorf("missing verifiers")
	}
	for _, v := range ds.Verifiers {
		if err := verifier.Validate(v); err != nil {
			return nil, err
		}
	}
	if len(ds.Envelope.Signatures) == 0 {
		return nil, fmt.Errorf("envelope missing signatures")
	}
	allPubKeyBytes := make(map[*pb.Verifier][]byte, 0)
	for _, v := range ds.Verifiers {
		pubKey := v.GetPublicKey()
		cert := v.GetX509Certificate()
		if pubKey != nil {
			allPubKeyBytes[v] = pubKey.RawBytes
		} else {
			allPubKeyBytes[v] = cert.RawBytes
		}
	}
	signerVerifiers, err := verifyEnvelope(allPubKeyBytes, ds.Envelope)
	if err != nil {
		return nil, err
	}
	payloadHash := sha256.Sum256(ds.Envelope.Payload)

	return &pb.DSSELogEntryV0_0_2{
		PayloadHash: &v1.HashOutput{
			Algorithm: v1.HashAlgorithm_SHA2_256,
			Digest:    payloadHash[:],
		},
		Signatures: signerVerifiers,
	}, nil
}

// verifyEnvelope takes in an array of possible key bytes and attempts to parse them as x509 public keys.
// it then uses these to verify the envelope and makes sure that every signature on the envelope is verified.
// it returns a list of SignatureAndVerifier mapping each signature in the envelope to a provided verifier
func verifyEnvelope(allPubKeyBytes map[*pb.Verifier][]byte, pbenv *pbdsse.Envelope) ([]*pb.Signature, error) {
	env := FromProto(pbenv)
	savs := make([]*pb.Signature, 0, len(allPubKeyBytes))
	// generate a fake id for these keys so we can get back to the key bytes and match them to their corresponding signature
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}

	for v, pubKeyBytes := range allPubKeyBytes {
		if len(allSigs) == 0 {
			break // if all signatures have been verified, do not attempt anymore
		}
		key, err := x509.NewPublicKey(bytes.NewReader(pubKeyBytes))
		if err != nil {
			return nil, fmt.Errorf("could not parse public key as x509: %w", err)
		}

		vfr, err := signature.LoadVerifier(key.CryptoPubKey(), crypto.SHA256)
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
			savs = append(savs, &pb.Signature{
				Content:  sigBytes,
				Verifier: v,
			})
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

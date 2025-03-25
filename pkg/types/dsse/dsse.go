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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	pb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/pkg/pki/x509"
	"github.com/sigstore/rekor-tiles/pkg/types/verifier"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
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
	envelope := &dsse.Envelope{}
	if err := json.Unmarshal([]byte(ds.Envelope), envelope); err != nil {
		return err
	}
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("envelope missing signatures")
	}
	allPubKeyBytes := make([][]byte, 0)
	for _, verifier := range ds.Verifier {
		pubKey := verifier.GetPublicKey()
		cert := verifier.GetX509Certificate()
		if pubKey != nil {
			allPubKeyBytes = append(allPubKeyBytes, pubKey.RawBytes)
		} else {
			allPubKeyBytes = append(allPubKeyBytes, cert.RawBytes)
		}
	}
	_, err := verifyEnvelope(allPubKeyBytes, envelope)
	if err != nil {
		return err
	}
	return nil
}

// verifyEnvelope takes in an array of possible key bytes and attempts to parse them as x509 public keys.
// it then uses these to verify the envelope and makes sure that every signature on the envelope is verified.
// it returns a map of verifiers indexed by the signature the verifier corresponds to.
// Copied from https://github.com/sigstore/rekor/blob/73dba7c07d0747f00119417fc0ff994a393f97b2/pkg/types/dsse/v0.0.1/entry.go#L364-L403
func verifyEnvelope(allPubKeyBytes [][]byte, env *dsse.Envelope) (map[string]*x509.PublicKey, error) {
	// generate a fake id for these keys so we can get back to the key bytes and match them to their corresponding signature
	verifierBySig := make(map[string]*x509.PublicKey)
	allSigs := make(map[string]struct{})
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}

	for _, pubKeyBytes := range allPubKeyBytes {
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
			verifierBySig[accept.Sig.Sig] = key
		}
	}

	if len(allSigs) > 0 {
		return nil, errors.New("all signatures must have a key that verifies it")
	}

	return verifierBySig, nil
}

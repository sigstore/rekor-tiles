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
	"crypto"
	"fmt"

	"github.com/sigstore/rekor-tiles/pkg/pki/x509"
	"github.com/sigstore/sigstore/pkg/signature"
)

// CheckEntryAlgorithms checks that the combination public key and message
// digest algorithm are allowed given an algorithm registry.
func CheckEntryAlgorithms(keyObj *x509.PublicKey, alg crypto.Hash, algorithmRegistry *signature.AlgorithmRegistryConfig) (bool, error) {
	publicKey := keyObj.CryptoPubKey()
	// Check if all the verifiers public keys (together with the
	// artifactHashValue) are allowed according to the policy
	isPermitted, err := algorithmRegistry.IsAlgorithmPermitted(publicKey, alg)
	if err != nil {
		return false, fmt.Errorf("checking if algorithm is permitted: %w", err)
	}
	if !isPermitted {
		return false, nil
	}
	return true, nil
}

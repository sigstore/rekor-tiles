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

package algorithmregistry

import (
	"crypto"
	"fmt"
	"slices"
	"sort"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	// AllowedClientSigningAlgorithms is the default set of supported signing
	// algorithms for log entry signatures.
	// When adding a new PublicKeyDetails, hashAlgorithmOrder must be updated
	// if it uses a hash algorithm not specified in hashAlgorithmOrder.
	AllowedClientSigningAlgorithms = []v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256,
		v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
		v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
		v1.PublicKeyDetails_PKIX_ED25519,
		v1.PublicKeyDetails_PKIX_ED25519_PH,
	}
	// Opinionated ordering of hash algorithms from oldest and weakest to newest and strongest.
	// Must be updated if AllowedClientSigningAlgorithms is updated with a new digest.
	// Used to select payload hash algorithm for entry with multiple signatures.
	hashAlgorithmOrder = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
)

// AlgorithmRegistry accepts a list of algorithms as strings, parses and formats them into a registry.
func AlgorithmRegistry(algorithmOptions []string) (*signature.AlgorithmRegistryConfig, error) {
	var algorithms []v1.PublicKeyDetails
	if algorithmOptions == nil {
		algorithms = AllowedClientSigningAlgorithms
	} else {
		for _, a := range algorithmOptions {
			algorithm, err := signature.ParseSignatureAlgorithmFlag(a)
			if err != nil {
				return nil, fmt.Errorf("parsing signature algorithm flag: %w", err)
			}
			algorithms = append(algorithms, algorithm)
		}
	}
	algorithmsStr := make([]string, len(algorithms))
	var err error
	for i, a := range algorithms {
		algorithmsStr[i], err = signature.FormatSignatureAlgorithmFlag(a)
		if err != nil {
			return nil, fmt.Errorf("formatting signature algorithm flag: %w", err)
		}
	}
	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig(algorithms)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm registry: %w", err)
	}
	return algorithmRegistry, nil
}

// CheckEntryAlgorithms checks that the combination public key and message
// digest algorithm are allowed given an algorithm registry.
func CheckEntryAlgorithms(pubKey crypto.PublicKey, alg crypto.Hash, algorithmRegistry *signature.AlgorithmRegistryConfig) (bool, error) {
	// Check if all the verifiers public keys (together with the
	// artifactHashValue) are allowed according to the policy
	isPermitted, err := algorithmRegistry.IsAlgorithmPermitted(pubKey, alg)
	if err != nil {
		return false, fmt.Errorf("checking if algorithm is permitted: %w", err)
	}
	if !isPermitted {
		return false, nil
	}
	return true, nil
}

// SelectHashAlgorithm picks the newest and strongest hash algorithm.
func SelectHashAlgorithm(algs []crypto.Hash) (crypto.Hash, error) {
	if len(algs) == 0 {
		return crypto.Hash(0), fmt.Errorf("hash algorithm slice is empty")
	}
	// sort from weakest to strongest
	// unknown algorithms will be sorted first in the array
	sort.Slice(algs, func(i, j int) bool {
		return slices.Index(hashAlgorithmOrder, algs[i]) < slices.Index(hashAlgorithmOrder, algs[j])
	})
	// select the strongest algorithm. Check it's a known algorithm, in case only
	// unknown algorithms were provided.
	strongest := algs[len(algs)-1]
	if slices.Index(hashAlgorithmOrder, strongest) == -1 {
		return crypto.Hash(0), fmt.Errorf("no known hash algorithms provided")
	}
	return strongest, nil
}

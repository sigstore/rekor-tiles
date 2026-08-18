/*
Copyright 2025 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Copied from https://github.com/sigstore/rekor/blob/c820fcaf3afdc91f0acf6824d55c1ac7df249df1/pkg/signer/signer.go

package signerverifier

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

// New returns a SignerVerifier for the given KMS provider, Tink, or a private key file on disk.
//
// KMS providers are loaded by importing the corresponding cloud-specific package,
// and the Tink key encryption key provider is supplied by that package through
// WithKEKProvider, which keeps this package free of cloud SDK dependencies.
func New(ctx context.Context, opts ...Option) (signature.SignerVerifier, error) {
	sc := &signerVerifierConfig{}
	for _, o := range opts {
		o(sc)
	}
	switch {
	case slices.ContainsFunc(kms.SupportedProviders(),
		func(s string) bool {
			return strings.HasPrefix(sc.kms, s)
		}):
		return kms.Get(ctx, sc.kms, sc.kmsHash, sc.kmsRPCOpts...)
	case sc.tinkKEKURI != "":
		return newTinkSignerVerifier(ctx, sc.kekPrefix, sc.kekProvider, sc.tinkKEKURI, sc.tinkKeysetPath)
	case sc.filePath != "":
		return NewFileSignerVerifier(sc.filePath, sc.password)
	default:
		return nil, fmt.Errorf("insufficient signing parameters provided, must configure one of file, KMS, or Tink signer-verifiers")
	}
}

type signerVerifierConfig struct {
	filePath       string
	password       string
	kms            string
	kmsHash        crypto.Hash
	kmsRPCOpts     []signature.RPCOption
	tinkKEKURI     string
	tinkKeysetPath string
	kekPrefix      string
	kekProvider    KEKProvider
}

type Option func(*signerVerifierConfig)

// WithFile configures a file-based signer-verifier with an optional password.
func WithFile(filePath, password string) Option {
	return func(sc *signerVerifierConfig) {
		sc.filePath = filePath
		sc.password = password
	}
}

// WithKMS configures a KMS signer-verifier. Providers that need per-call RPC
// options, such as GCP KMS retries, pass them as rpcOpts; others pass none.
func WithKMS(kms string, hash crypto.Hash, rpcOpts ...signature.RPCOption) Option {
	return func(sc *signerVerifierConfig) {
		sc.kms = kms
		sc.kmsHash = hash
		sc.kmsRPCOpts = rpcOpts
	}
}

// WithTink configures a Tink signer-verifier.
func WithTink(kekURI, keysetPath string) Option {
	return func(sc *signerVerifierConfig) {
		sc.tinkKEKURI = kekURI
		sc.tinkKeysetPath = keysetPath
	}
}

// WithKEKProvider supplies the Tink key encryption key provider for a cloud, along
// with the URI prefix it handles. A Tink KEK URI that does not carry that prefix is
// rejected, so a binary only resolves the clouds it wires in. Cloud-specific
// packages apply this option after the caller's so that it cannot be overridden.
func WithKEKProvider(prefix string, provider KEKProvider) Option {
	return func(sc *signerVerifierConfig) {
		sc.kekPrefix = prefix
		sc.kekProvider = provider
	}
}

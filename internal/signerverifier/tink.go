// Copyright 2025 The Sigstore Authors.
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

// Modified from https://github.com/sigstore/rekor/blob/c820fcaf3afdc91f0acf6824d55c1ac7df249df1/pkg/signer/tink.go

package signerverifier

import (
	"os"
	"path/filepath"

	tinkUtils "github.com/sigstore/sigstore/pkg/signature/tink"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/sigstore/sigstore/pkg/signature"
)

// NewTinkSignerVerifierWithHandle returns a signature.SignerVerifier that wraps crypto.Signer and a hash function.
// Provide a path to the encrypted keyset and a key handle for decrypting the keyset
func NewTinkSignerVerifierWithHandle(kek tink.AEAD, keysetPath string) (signature.SignerVerifier, error) {
	f, err := os.Open(filepath.Clean(keysetPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kh, err := keyset.Read(keyset.NewJSONReader(f), kek)
	if err != nil {
		return nil, err
	}
	signer, err := tinkUtils.KeyHandleToSigner(kh)
	if err != nil {
		return nil, err
	}
	return signature.LoadDefaultSignerVerifier(signer)
}

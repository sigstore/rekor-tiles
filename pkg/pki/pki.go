//
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

// Copied with modifications from https://github.com/sigstore/rekor/blob/73dba7c07d0747f00119417fc0ff994a393f97b2/pkg/pki/pki.go

package pki

import (
	"io"

	"github.com/sigstore/rekor-tiles/pkg/pki/identity"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// PublicKey Generic object representing a public key (regardless of format & algorithm)
type PublicKey interface {
	// CanonicalValue returns the canonicalized representation of the public key.
	CanonicalValue() ([]byte, error)
	// Subjects returns the subject URIs of the public key.
	Subjects() []string
	// Identities returns a list of typed keys and certificates.
	Identities() ([]identity.Identity, error)
}

// Signature Generic object representing a signature (regardless of format & algorithm)
type Signature interface {
	// CanonicalValue returns the canonicalized representation of the signature.
	CanonicalValue() ([]byte, error)
	// Verify verifies the signature.
	Verify(r io.Reader, k interface{}, opts ...sigsig.VerifyOption) error
}

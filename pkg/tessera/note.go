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

// Heavily borrowed from https://gist.githubusercontent.com/AlCutter/c6c69076dc55652e2d278900ccc1a5e7/raw/aac2bafc17a8efa162bd99b4453070b724779307/ecdsa_note.go - thanks, Al

package tessera

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/mod/sumdb/note"
)

// noteSigner uses an arbitrary sigstore signer to implement golang.org/x/mod/sumdb/note.Signer,
// which is used in Tessera to sign checkpoints in the signed notes format
// (https://github.com/C2SP/C2SP/blob/main/signed-note.md).
type noteSigner struct {
	name string
	hash uint32
	sign func(msg []byte) ([]byte, error)
}

// Name returns the server name associated with the key.
func (n *noteSigner) Name() string {
	return n.name
}

// KeyHash returns the key hash.
func (n *noteSigner) KeyHash() uint32 {
	return n.hash
}

// Sign returns a signature for the given message.
func (n *noteSigner) Sign(msg []byte) ([]byte, error) {
	return n.sign(msg)
}

// isValidName reports whether the name conforms to the spec for the origin string of the note text
// as defined in https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md#note-text.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// newNoteSigner converts a sigstore/sigstore/pkg/signature.Signer into a note.Signer.
func newNoteSigner(ctx context.Context, origin string, signer signature.Signer) (note.Signer, error) {
	if !isValidName(origin) {
		return &noteSigner{}, fmt.Errorf("invalid name %s", origin)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return &noteSigner{}, fmt.Errorf("getting public key: %w", err)
	}
	marshaledPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return &noteSigner{}, fmt.Errorf("marshalling public key: %w", err)
	}

	hash := sha256.Sum256(marshaledPubKey)

	sign := func(msg []byte) ([]byte, error) {
		return signer.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	}

	return &noteSigner{
		name: origin,
		hash: binary.BigEndian.Uint32(hash[:]),
		sign: sign,
	}, nil
}

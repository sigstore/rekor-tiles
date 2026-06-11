// Copyright 2026 The Sigstore Authors
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

//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/identity"
	"github.com/sigstore/rekor-tiles/v2/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	f_note "github.com/transparency-dev/formats/note"
	tlogproof "github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	signednote "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

var identityPosixConfig = backendConfig{
	ServerURL:   "http://localhost:3006",
	StorageURL:  "http://localhost:8001",
	ComposePath: "identity-posix-compose.yml",
}

func TestIdentityPOSIX(t *testing.T) {
	t.Run("ReadWrite", func(t *testing.T) {
		testIdentityReadWrite(t, identityPosixConfig)
	})
}

func testIdentityReadWrite(t *testing.T, config backendConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// get verifier needed for both read and write
	serverPubKeyPEM, err := os.ReadFile(defaultServerPublicKey)
	assert.NoError(t, err)
	serverPubKey, err := cryptoutils.UnmarshalPEMToPublicKey(serverPubKeyPEM)
	assert.NoError(t, err)
	verifier, err := signature.LoadDefaultVerifier(serverPubKey)
	assert.NoError(t, err)

	reader, err := read.NewReader(config.StorageURL, defaultRekorHostname, verifier)
	assert.NoError(t, err)
	checkpoint, _, err := reader.ReadCheckpoint(ctx)
	assert.NoError(t, err)
	initialTreeSize := checkpoint.Size

	// Generate a valid ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	pubBytes, err := cryptoutils.MarshalPublicKeyToDER(pub)
	assert.NoError(t, err)

	// Create a message hash
	message := []byte("hello world")
	msgHash := sha256.Sum256(message)

	contextKey := sha256.Sum256([]byte("foo"))
	contextVal := sha256.Sum256([]byte("bar"))

	// Compute signature over "c2sp.org/identity-transparency/v1\x00" || H(msgHash) || H(contextKey) || H(contextVal)
	payload := []byte("c2sp.org/identity-transparency/v1\x00")
	msgDoubleHash := sha256.Sum256(msgHash[:])
	payload = append(payload, msgDoubleHash[:]...)

	keyDoubleHash := sha256.Sum256(contextKey[:])
	valDoubleHash := sha256.Sum256(contextVal[:])
	payload = append(payload, keyDoubleHash[:]...)
	payload = append(payload, valDoubleHash[:]...)

	sig := ed25519.Sign(priv, payload)

	req := &pb.IdentityRequestV001{
		Credential: &pb.IdentityRequestV001_PublicKey{
			PublicKey: &pb.PublicKeyCredential{
				PublicKey: pubBytes,
				Signature: sig,
			},
		},
		Message: msgHash[:],
		Context: []*pb.ContextEntry{
			{Key: contextKey[:], Value: contextVal[:]},
		},
	}

	b, err := protojson.Marshal(req)
	assert.NoError(t, err)

	url := fmt.Sprintf("%s/api/v2/log/entries", config.ServerURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	assert.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	assert.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Expected 201 Created, got: %s", string(respBody))

	// Ensure the response is a tlog-proof object
	respStr := string(respBody)
	t.Logf("Response body: %s", respStr)

	var pr tlogproof.TLogProof
	err = pr.Unmarshal(respBody)
	assert.NoError(t, err, "Response body should parse as TLogProof")

	noteVerifier, err := note.NewNoteVerifier(defaultRekorHostname, verifier)
	assert.NoError(t, err)

	witnessNoteVerifier, err := f_note.NewVerifierForCosignatureV1(defaultWitnessVKey)
	assert.NoError(t, err)

	noteVerifiers := []signednote.Verifier{noteVerifier, witnessNoteVerifier}

	cp, parsedNote, err := verify.VerifyWitnessedCheckpoint(string(pr.Checkpoint), noteVerifiers[0], noteVerifiers[1:]...)
	assert.NoError(t, err, "Checkpoint should be valid")
	assert.Len(t, parsedNote.Sigs, 2, "Expected 2 valid signatures, from the log and witness")

	expectedExtraData := fmt.Sprintf("%s:%s", hex.EncodeToString(contextKey[:]), hex.EncodeToString(contextVal[:]))
	assert.Equal(t, []byte(expectedExtraData), pr.ExtraData, "ExtraData should contain the formatted context strings")

	ctxMap := make(map[string]string)
	for _, c := range req.Context {
		ctxMap[hex.EncodeToString(c.Key)] = hex.EncodeToString(c.Value)
	}

	leafHash, err := identity.ToEntryHash(pubBytes, sig, req.Message, ctxMap)
	assert.NoError(t, err)

	var hashes [][]byte
	for _, h := range pr.Hashes {
		hCopy := h
		hashes = append(hashes, hCopy[:])
	}

	err = proof.VerifyInclusion(rfc6962.DefaultHasher, pr.Index, cp.Size, leafHash, hashes, cp.Hash)
	assert.NoError(t, err, "Inclusion proof should be valid")

	assert.Equal(t, initialTreeSize, pr.Index, "Index should match the tree size from before uploading")
}

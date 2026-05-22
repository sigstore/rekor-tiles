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

package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	pb "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	f_log "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	note "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestVerifyInclusionProof(t *testing.T) {
	hash := []byte{89, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
	rootHash := []byte{91, 225, 117, 141, 210, 34, 138, 207, 175, 37, 70, 180, 182, 206, 138, 164, 12, 130, 163, 116, 143, 61, 203, 85, 14, 13, 103, 186, 52, 240, 42, 69}
	body := []byte("{\"apiVersion\":\"0.0.1\",\"kind\":\"rekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8\"}},\"signature\":{\"content\":\"MEYCIQD/PdPQmKWC1+0BNEd5gKvQGr1xxl3ieUffv3jk1zzJKwIhALBj3xfAyWxlz4jpoIEIV1UfK9vnkUUOSoeZxBZPHKPC\",\"format\":\"x509\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTU9jVGZSQlM5amlYTTgxRlo4Z20vMStvbWVNdwptbi8zNDcvNTU2Zy9scmlTNzJ1TWhZOUxjVCs1VUo2ZkdCZ2xyNVo4TDBKTlN1YXN5ZWQ5T3RhUnZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"}}}}")

	for _, test := range []struct {
		name    string
		proof   *pbs.InclusionProof
		logSize uint64
		wantErr bool
	}{
		{
			name: "valid inclusionproof",
			proof: &pbs.InclusionProof{
				LogIndex: 1,
				TreeSize: 2,
				Hashes: [][]byte{
					[]byte(hash),
				},
			},
			logSize: 2,
			wantErr: false,
		},
		{
			name: "invalid hash",
			proof: &pbs.InclusionProof{
				LogIndex: 1,
				TreeSize: 2,
				Hashes: [][]byte{
					[]byte([]byte{0, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}),
				},
			},
			logSize: 2,
			wantErr: true,
		},
		{
			name: "inclusion index beyond log size",
			proof: &pbs.InclusionProof{
				LogIndex: 1,
				TreeSize: 2,
				Hashes: [][]byte{
					[]byte(hash),
				},
			},
			logSize: 1,
			wantErr: true,
		},
		{
			name: "wrong proof size",
			proof: &pbs.InclusionProof{
				LogIndex: 1,
				TreeSize: 2,
				Hashes: [][]byte{
					[]byte(hash),
				},
			},
			logSize: 3,
			wantErr: true,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			checkpoint := &f_log.Checkpoint{
				Size: test.logSize,
				Hash: rootHash,
			}

			entry := &pbs.TransparencyLogEntry{
				LogIndex:          1,
				InclusionProof:    test.proof,
				CanonicalizedBody: body,
			}
			gotErr := VerifyInclusionProof(entry, checkpoint)
			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyCheckpoint = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}

func getTestEntry(t *testing.T, signer signature.Signer, hostname string, otherSigners ...note.Signer) *pbs.TransparencyLogEntry {
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, signer)
	if err != nil {
		t.Fatal(err)
	}
	rootHash := sha256.Sum256([]byte{1, 2, 3})
	cpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   uint64(2),
		Hash:   rootHash[:],
	}.Marshal()

	n, err := note.Sign(&note.Note{Text: string(cpRaw)}, append([]note.Signer{noteSigner}, otherSigners...)...)
	if err != nil {
		t.Fatal(err)
	}

	return &pbs.TransparencyLogEntry{
		InclusionProof: &pbs.InclusionProof{
			Checkpoint: &pbs.Checkpoint{
				Envelope: string(n),
			},
		},
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	hostname := "rekor.localhost"
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	otherSigner, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	noteVerifier, err := rekornote.NewNoteVerifier(hostname, sv)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		checkpoint string
		wantErr    bool
	}{
		{
			name:       "valid checkpoint",
			checkpoint: getTestEntry(t, sv, hostname).GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    false,
		},
		{
			name:       "hostname mismatch",
			checkpoint: getTestEntry(t, sv, "other.host").GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    true,
		},
		{
			name:       "signature mismatch",
			checkpoint: getTestEntry(t, otherSigner, hostname).GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    true,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			_, gotErr := VerifyCheckpoint(test.checkpoint, noteVerifier)
			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyCheckpoint = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}

func TestVerifyWitnessedCheckpoint(t *testing.T) {
	hostname := "rekor.localhost"
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	witnessOrigin := "test-witness"
	privKey, pubKey, err := note.GenerateKey(rand.Reader, witnessOrigin)
	if err != nil {
		log.Fatalf("error generating key: %v", err)
	}
	witnessSigner, err := f_note.NewSignerForCosignatureV1(privKey)
	if err != nil {
		t.Fatal(err)
	}
	witnessVerifier, err := f_note.NewVerifierForCosignatureV1(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	otherSigner, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}
	otherNoteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, otherSigner)
	if err != nil {
		t.Fatal(err)
	}

	noteVerifier, err := rekornote.NewNoteVerifier(hostname, sv)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		checkpoint string
		wantErr    bool
		wantLength int
	}{
		{
			name:       "valid witnessed checkpoint",
			checkpoint: getTestEntry(t, sv, hostname, witnessSigner).GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    false,
			wantLength: 2,
		},
		{
			name:       "mismatched log verifier with witness",
			checkpoint: getTestEntry(t, otherSigner, hostname, witnessSigner).GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    true,
		},
		{
			name:       "only one valid signature, from log",
			checkpoint: getTestEntry(t, sv, hostname, otherNoteSigner).GetInclusionProof().GetCheckpoint().GetEnvelope(),
			wantErr:    false,
			wantLength: 1,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			_, note, gotErr := VerifyWitnessedCheckpoint(test.checkpoint, noteVerifier, witnessVerifier)
			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyCheckpoint = %t, wantErr %t", gotErr, test.wantErr)
			}
			if gotErr == nil {
				assert.Len(t, note.Sigs, test.wantLength)
			}
		})
	}
}

func TestVerifyLogEntry(t *testing.T) {
	hostname := "rekor.localhost"
	hash := []byte{89, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
	rootHash := []byte{91, 225, 117, 141, 210, 34, 138, 207, 175, 37, 70, 180, 182, 206, 138, 164, 12, 130, 163, 116, 143, 61, 203, 85, 14, 13, 103, 186, 52, 240, 42, 69}
	body := []byte("{\"apiVersion\":\"0.0.1\",\"kind\":\"rekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8\"}},\"signature\":{\"content\":\"MEYCIQD/PdPQmKWC1+0BNEd5gKvQGr1xxl3ieUffv3jk1zzJKwIhALBj3xfAyWxlz4jpoIEIV1UfK9vnkUUOSoeZxBZPHKPC\",\"format\":\"x509\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTU9jVGZSQlM5amlYTTgxRlo4Z20vMStvbWVNdwptbi8zNDcvNTU2Zy9scmlTNzJ1TWhZOUxjVCs1VUo2ZkdCZ2xyNVo4TDBKTlN1YXN5ZWQ5T3RhUnZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"}}}}")

	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	noteVerifier, err := rekornote.NewNoteVerifier(hostname, sv)
	if err != nil {
		t.Fatal(err)
	}

	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, sv)
	if err != nil {
		t.Fatal(err)
	}
	cpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   uint64(2),
		Hash:   rootHash,
	}.Marshal()

	n, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}

	proof := &pbs.InclusionProof{
		LogIndex: 1,
		TreeSize: 2,
		Hashes: [][]byte{
			[]byte(hash),
		},
		Checkpoint: &pbs.Checkpoint{
			Envelope: string(n),
		},
	}

	entry := &pbs.TransparencyLogEntry{
		CanonicalizedBody: body,
		InclusionProof:    proof,
		LogIndex:          1,
	}

	gotErr := VerifyLogEntry(entry, noteVerifier)
	assert.NoError(t, gotErr)
}

func TestVerifyLogEntryWithEntryHash(t *testing.T) {
	hostname := "rekor.localhost"
	hash := []byte{89, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
	rootHash := []byte{91, 225, 117, 141, 210, 34, 138, 207, 175, 37, 70, 180, 182, 206, 138, 164, 12, 130, 163, 116, 143, 61, 203, 85, 14, 13, 103, 186, 52, 240, 42, 69}
	body := []byte("{\"apiVersion\":\"0.0.1\",\"kind\":\"rekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8\"}},\"signature\":{\"content\":\"MEYCIQD/PdPQmKWC1+0BNEd5gKvQGr1xxl3ieUffv3jk1zzJKwIhALBj3xfAyWxlz4jpoIEIV1UfK9vnkUUOSoeZxBZPHKPC\",\"format\":\"x509\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTU9jVGZSQlM5amlYTTgxRlo4Z20vMStvbWVNdwptbi8zNDcvNTU2Zy9scmlTNzJ1TWhZOUxjVCs1VUo2ZkdCZ2xyNVo4TDBKTlN1YXN5ZWQ5T3RhUnZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"}}}}")

	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}

	noteVerifier, err := rekornote.NewNoteVerifier(hostname, sv)
	if err != nil {
		t.Fatal(err)
	}

	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, sv)
	if err != nil {
		t.Fatal(err)
	}
	cpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   uint64(2),
		Hash:   rootHash,
	}.Marshal()

	n, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}

	proof := &pbs.InclusionProof{
		LogIndex: 1,
		TreeSize: 2,
		Hashes: [][]byte{
			[]byte(hash),
		},
		Checkpoint: &pbs.Checkpoint{
			Envelope: string(n),
		},
	}

	// Entry intentionally omits CanonicalizedBody to confirm the new function
	// does not depend on it.
	entry := &pbs.TransparencyLogEntry{
		InclusionProof: proof,
		LogIndex:       1,
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(body)
	assert.NoError(t, VerifyLogEntryWithEntryHash(entry, noteVerifier, leafHash))

	// Wrong leaf hash should fail inclusion verification.
	wrongLeaf := rfc6962.DefaultHasher.HashLeaf([]byte("not the body"))
	assert.Error(t, VerifyLogEntryWithEntryHash(entry, noteVerifier, wrongLeaf))
}

// TestRecomputeLeafEndToEnd drives the rekor-v2-spec §6.1.4 "Recompute the
// leaf" path producer-to-consumer: a HashedRekordRequestV002 is canonicalized
// the same way the log service does, the resulting leaf hash anchors a signed
// size-1 checkpoint, and the bundle-signed inputs are then re-fed through
// hashedrekord.ToEntryHash + VerifyLogEntryWithEntryHash. This catches
// any future divergence between the client reconstruction and server
// canonicalization (protojson field ordering, defaults, jsoncanonicalizer
// behavior, etc.) that the isolated unit tests would silently miss.
func TestRecomputeLeafEndToEnd(t *testing.T) {
	hostname := "rekor.localhost"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256([]byte("end-to-end test payload"))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, payloadDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	req := &pb.HashedRekordRequestV002{
		Digest: payloadDigest[:],
		Signature: &pb.Signature{
			Content: sig,
			Verifier: &pb.Verifier{
				Verifier: &pb.Verifier_PublicKey{
					PublicKey: &pb.PublicKey{RawBytes: pubKeyDER},
				},
				KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			},
		},
	}

	algReg, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256})
	if err != nil {
		t.Fatal(err)
	}
	logEntry, err := hashedrekord.ToLogEntry(req, algReg)
	if err != nil {
		t.Fatal(err)
	}

	// Server-side leaf hash: protojson.Marshal -> jsoncanonicalizer.Transform
	// -> rfc6962 HashLeaf, exactly mirroring internal/server/service.go.
	serialized, err := protojson.Marshal(logEntry)
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(serialized)
	if err != nil {
		t.Fatal(err)
	}
	serverLeafHash := rfc6962.DefaultHasher.HashLeaf(canonicalized)

	cpSV, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, cpSV)
	if err != nil {
		t.Fatal(err)
	}
	noteVerifier, err := rekornote.NewNoteVerifier(hostname, cpSV)
	if err != nil {
		t.Fatal(err)
	}
	cpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   1,
		Hash:   serverLeafHash,
	}.Marshal()
	signedCp, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}
	tle := &pbs.TransparencyLogEntry{
		LogIndex: 0,
		InclusionProof: &pbs.InclusionProof{
			LogIndex: 0,
			TreeSize: 1,
			Hashes:   [][]byte{},
			Checkpoint: &pbs.Checkpoint{
				Envelope: string(signedCp),
			},
		},
	}

	clientLeafHash, err := hashedrekord.ToEntryHash(req.Digest, req.Signature)
	assert.NoError(t, err)
	assert.Equal(t, serverLeafHash, clientLeafHash, "client-reconstructed leaf hash must equal server-canonicalized leaf hash")

	assert.NoError(t, VerifyLogEntryWithEntryHash(tle, noteVerifier, clientLeafHash))

	// Tampered digest must produce a different leaf hash that fails inclusion.
	tamperedDigest := append([]byte(nil), req.Digest...)
	tamperedDigest[0] ^= 0x01
	tamperedLeafHash, err := hashedrekord.ToEntryHash(tamperedDigest, req.Signature)
	assert.NoError(t, err)
	assert.NotEqual(t, clientLeafHash, tamperedLeafHash)
	assert.Error(t, VerifyLogEntryWithEntryHash(tle, noteVerifier, tamperedLeafHash))
}

func TestVerifyConsistencyProof(t *testing.T) {
	hostname := "rekor.localhost"
	root1, err := hex.DecodeString("59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c")
	if err != nil {
		t.Fatal(err)
	}
	root2, err := hex.DecodeString("5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45")
	if err != nil {
		t.Fatal(err)
	}
	consistencyHashes, err := hex.DecodeString("d3be742c8d73e2dd3c5635843e987ad3dfb3837616f412a07bf730c3ad73f5cb")
	if err != nil {
		t.Fatal(err)
	}

	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatal(err)
	}
	noteVerifier, err := rekornote.NewNoteVerifier(hostname, sv)
	if err != nil {
		t.Fatal(err)
	}
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), hostname, sv)
	if err != nil {
		t.Fatal(err)

	}

	oldCpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   1,
		Hash:   root1,
	}.Marshal()
	oldCp, err := note.Sign(&note.Note{Text: string(oldCpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}

	newCpRaw := f_log.Checkpoint{
		Origin: hostname,
		Size:   2,
		Hash:   root2,
	}.Marshal()
	newCp, err := note.Sign(&note.Note{Text: string(newCpRaw)}, noteSigner)
	if err != nil {
		t.Fatal(err)
	}

	gotErr := VerifyConsistencyProofWithCheckpoints([][]byte{consistencyHashes}, string(oldCp), string(newCp), noteVerifier)
	assert.NoError(t, gotErr)

	gotErr = VerifyConsistencyProof([][]byte{consistencyHashes}, 1, root1, string(newCp), noteVerifier)
	assert.NoError(t, gotErr)
}

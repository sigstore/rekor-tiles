package verify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	pbs "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekornote "github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	f_log "github.com/transparency-dev/formats/log"
	note "golang.org/x/mod/sumdb/note"
)

func TestVerifyInclusionProof(t *testing.T) {
	hash := []byte{89, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
	rootHash := []byte{91, 225, 117, 141, 210, 34, 138, 207, 175, 37, 70, 180, 182, 206, 138, 164, 12, 130, 163, 116, 143, 61, 203, 85, 14, 13, 103, 186, 52, 240, 42, 69}
	body, err := base64.StdEncoding.DecodeString("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19")
	if err != nil {
		t.Fatal(err)
	}

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

func getTestEntry(t *testing.T, signer signature.Signer, hostname string) *pbs.TransparencyLogEntry {
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

	n, err := note.Sign(&note.Note{Text: string(cpRaw)}, noteSigner)
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
		name    string
		entry   *pbs.TransparencyLogEntry
		wantErr bool
	}{
		{
			name:    "valid checkpoint",
			entry:   getTestEntry(t, sv, hostname),
			wantErr: false,
		},
		{
			name:    "hostname mismatch",
			entry:   getTestEntry(t, sv, "other.host"),
			wantErr: true,
		},
		{
			name:    "signature mismatch",
			entry:   getTestEntry(t, otherSigner, hostname),
			wantErr: true,
		},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			_, gotErr := VerifyCheckpoint(test.entry, noteVerifier)
			if (gotErr != nil) != test.wantErr {
				t.Fatalf("VerifyCheckpoint = %t, wantErr %t", gotErr, test.wantErr)
			}
		})
	}
}

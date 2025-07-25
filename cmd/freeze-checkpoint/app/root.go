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

package app

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	gcs "cloud.google.com/go/storage"
	"github.com/sigstore/rekor-tiles/internal/signerverifier"
	rekornote "github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	logformat "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
)

const (
	frozenString = "Log frozen — "
)

var rootCmd = &cobra.Command{
	Use:   "freeze-checkpoint",
	Short: "Freeze the log checkpoint",
	Long:  `Add an extension line to the final checkpoint to indicate to consumers that no more checkpoints are going to be published. Only supported for GCP.`,
	Run: func(cmd *cobra.Command, _ []string) {
		ctx := cmd.Context()

		if viper.GetString("gcp-bucket") == "" {
			slog.Error("must provide --gcs-bucket")
			os.Exit(1)
		}
		if viper.GetString("hostname") == "" {
			slog.Error("must provide --hostname for the rekor server's identity")
			os.Exit(1)
		}

		sv, err := getSignerVerifier(ctx)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		noteSigner, err := getNoteSigner(ctx, sv)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		noteVerifier, err := getNoteVerifier(sv)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		objReader, objWriter, err := objectAccess(ctx)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		checkpoint, err := getCheckpoint(objReader, noteVerifier)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		if checkpoint == nil {
			slog.Info("log is already frozen")
			return
		}

		err = updateCheckpoint(objWriter, noteSigner, checkpoint)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		if err := objWriter.Close(); err != nil {
			slog.Error("closing object writer", "error", err.Error())
			os.Exit(1)
		}
		slog.Info("Log frozen")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().String("gcp-bucket", "", "GCS bucket for tile and checkpoint storage")
	rootCmd.Flags().String("hostname", "", "public hostname, used as the checkpoint origin")
	rootCmd.Flags().String("signer-filepath", "", "path to the signing key")
	rootCmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	rootCmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of awskms://keyname, azurekms://keyname, gcpkms://keyname, or hashivault://keyname")
	rootCmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	rootCmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset. Valid options are [aws-kms://keyname, gcp-kms://keyname]")
	rootCmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")

	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

var hashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

func getSignerVerifier(ctx context.Context) (signature.SignerVerifier, error) {
	var opts []signerverifier.Option
	switch {
	case viper.GetString("signer-filepath") != "":
		opts = []signerverifier.Option{signerverifier.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}
	case viper.GetString("signer-kmskey") != "":
		kmshash := viper.GetString("signer-kmshash")
		hashAlg, ok := hashAlgMap[kmshash]
		if !ok {
			return nil, fmt.Errorf("invalid hash algorithm for --signer-kmshash: %s", kmshash)
		}
		opts = []signerverifier.Option{signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg)}
	case viper.GetString("signer-tink-kek-uri") != "":
		opts = []signerverifier.Option{signerverifier.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}
	default:
		return nil, fmt.Errorf("must provide a signer using a file, KMS, or Tink")
	}
	signerVerifier, err := signerverifier.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing key signer: %w", err)
	}
	return signerVerifier, nil
}

func getNoteSigner(ctx context.Context, signer signature.Signer) (note.Signer, error) {
	origin := viper.GetString("hostname")
	noteSigner, err := rekornote.NewNoteSigner(ctx, origin, signer)
	if err != nil {
		return nil, fmt.Errorf("initializing note signer: %w", err)
	}
	return noteSigner, nil
}

func getNoteVerifier(verifier signature.Verifier) (note.Verifier, error) {
	origin := viper.GetString("hostname")
	noteVerifier, err := rekornote.NewNoteVerifier(origin, verifier)
	if err != nil {
		return nil, fmt.Errorf("initializing note verifier: %w", err)
	}
	return noteVerifier, nil
}

func objectAccess(ctx context.Context) (*gcs.Reader, *gcs.Writer, error) {
	client, err := gcs.NewClient(ctx, gcs.WithJSONReads())
	if err != nil {
		return nil, nil, fmt.Errorf("getting GCS client: %w", err)
	}
	bucketName := viper.GetString("gcp-bucket")
	object := client.Bucket(bucketName).Object(layout.CheckpointPath)
	objReader, err := object.NewReader(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting object reader: %w", err)
	}
	contentType := "text/plain; charset=utf-8"
	objWriter := object.NewWriter(ctx)
	objWriter.ContentType = contentType
	return objReader, objWriter, nil
}

func getCheckpoint(objReader *gcs.Reader, noteVerifier note.Verifier) (*logformat.Checkpoint, error) {
	rawCheckpoint, err := io.ReadAll(objReader)
	if err != nil {
		return nil, fmt.Errorf("reading object: %w", err)
	}
	noteObj, err := note.Open(rawCheckpoint, note.VerifierList(noteVerifier))
	if err != nil {
		return nil, fmt.Errorf("opening checkpoint: %w", err)
	}
	checkpoint := logformat.Checkpoint{}
	rest, err := checkpoint.Unmarshal([]byte(noteObj.Text))
	if err != nil {
		return nil, fmt.Errorf("parsing checkpoint: %w", err)
	}
	if strings.Contains(string(rest), frozenString) {
		return nil, nil
	}
	return &checkpoint, nil
}

// updateCheckpoint writes an extension line to the checkpoint note to indicate the checkpoint is frozen,
// re-signs it and re-uploads it to the GCS backend.
func updateCheckpoint(objWriter *gcs.Writer, noteSigner note.Signer, checkpoint *logformat.Checkpoint) error {
	// Marshaled checkpoint contains the origin, size, and hash of the checkpoint, not the signatures.
	// The final checkpoint object will contain the origin, size, hash, extension line, and signature.
	buf := bytes.NewBuffer(checkpoint.Marshal())
	buf.WriteString(frozenString)
	now := time.Now().UTC().Format(time.UnixDate)
	buf.WriteString(now)
	buf.WriteString("\n")
	signedNote, err := note.Sign(&note.Note{Text: buf.String()}, noteSigner)
	if err != nil {
		return fmt.Errorf("re-signing checkpoint: %w", err)
	}
	if _, err := objWriter.Write(signedNote); err != nil {
		return fmt.Errorf("writing checkpoint: %w", err)
	}
	return nil
}

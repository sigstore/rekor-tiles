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

// Package config builds signer-verifier options from command line configuration.
package config

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"

	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
)

// ErrNoSigner is returned when no signer was configured.
var ErrNoSigner = errors.New("must provide a signer using a file, KMS, or Tink")

// InvalidHashError reports an unrecognized --signer-kmshash value.
type InvalidHashError struct {
	Algorithm string
}

func (e *InvalidHashError) Error() string {
	return fmt.Sprintf("invalid hash algorithm for --signer-kmshash: %s", e.Algorithm)
}

// LogError logs a configuration error from OptionsFromViper using the server
// convention, so that each error keeps its own message and structured attributes.
func LogError(err error) {
	var invalidHash *InvalidHashError
	switch {
	case errors.As(err, &invalidHash):
		slog.Error("invalid hash algorithm for --signer-kmshash", "algorithm", invalidHash.Algorithm)
	case errors.Is(err, ErrNoSigner):
		slog.Error("no signer configured; must provide a signer using a file, KMS, or Tink")
	default:
		slog.Error(err.Error())
	}
}

var hashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

// OptionsFromViper builds signer-verifier options from the signer-* configuration
// keys. Callers construct the signer-verifier themselves so that each command keeps
// its own error handling policy.
//
// rpcOpts carries provider-specific KMS RPC options and is only applied to the KMS
// signer-verifier. It is supplied by the caller rather than built here so that this
// package stays free of cloud SDK dependencies.
func OptionsFromViper(v *viper.Viper, rpcOpts ...signature.RPCOption) ([]sv.Option, error) {
	switch {
	case v.GetString("signer-filepath") != "":
		return []sv.Option{sv.WithFile(v.GetString("signer-filepath"), v.GetString("signer-password"))}, nil
	case v.GetString("signer-kmskey") != "":
		kmshash := v.GetString("signer-kmshash")
		hashAlg, ok := hashAlgMap[kmshash]
		if !ok {
			return nil, &InvalidHashError{Algorithm: kmshash}
		}
		return []sv.Option{sv.WithKMS(v.GetString("signer-kmskey"), hashAlg, rpcOpts...)}, nil
	case v.GetString("signer-tink-kek-uri") != "":
		return []sv.Option{sv.WithTink(v.GetString("signer-tink-kek-uri"), v.GetString("signer-tink-keyset-path"))}, nil
	default:
		return nil, ErrNoSigner
	}
}

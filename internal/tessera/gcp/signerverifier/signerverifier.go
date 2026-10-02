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

// Package signerverifier wires the GCP-specific signer-verifier dependencies into
// the shared internal/signerverifier package. Importing it loads the GCP KMS
// provider, and its New supplies the gcp-kms:// Tink key encryption key provider so
// that GCP callers need only this import.
package signerverifier

import (
	"context"
	"slices"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/signature"

	// imported by name for WithGoogleAPIClientOption; this also loads the GCP KMS
	// provider via its init() call
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// KEKScheme is the key encryption key URI prefix handled by GCP KMS.
const KEKScheme = "gcp-kms://"

// New returns a SignerVerifier configured for GCP, resolving Tink key encryption
// keys through GCP KMS. The KEK provider option is appended after the caller's, so
// it is authoritative and a caller cannot substitute another cloud's provider.
func New(ctx context.Context, opts ...sv.Option) (signature.SignerVerifier, error) {
	return sv.New(ctx, append(slices.Clone(opts), sv.WithKEKProvider(KEKScheme, newGCPKEK))...)
}

// newGCPKEK returns a Tink AEAD encryption key from GCP KMS.
func newGCPKEK(ctx context.Context, kmsKey string) (tink.AEAD, error) {
	gcpClient, err := gcpkms.NewClient(ctx, kmsKey)
	if err != nil {
		return nil, err
	}
	registry.RegisterKMSClient(gcpClient)
	return gcpClient.GetAEAD(kmsKey)
}

// KMSRPCOptions returns the retry options for GCP KMS calls, to be passed to WithKMS.
func KMSRPCOptions(retries uint, perRetryTimeout time.Duration) []signature.RPCOption {
	callOpts := []grpc_retry.CallOption{grpc_retry.WithMax(retries), grpc_retry.WithPerRetryTimeout(perRetryTimeout)}
	return []signature.RPCOption{
		gcp.WithGoogleAPIClientOption(option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))),
	}
}

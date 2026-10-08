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

// Package signerverifier wires the AWS-specific signer-verifier dependencies into
// the shared internal/signerverifier package. Importing it loads the AWS KMS
// provider, and its New supplies the aws-kms:// Tink key encryption key provider so
// that AWS callers need only this import.
package signerverifier

import (
	"context"
	"slices"

	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"

	// imported to load the AWS KMS provider via its init() call
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

// KEKScheme is the key encryption key URI prefix handled by AWS KMS.
const KEKScheme = "aws-kms://"

// New returns a SignerVerifier configured for AWS, resolving Tink key encryption
// keys through AWS KMS. The KEK provider option is appended after the caller's, so
// it is authoritative and a caller cannot substitute another cloud's provider.
func New(ctx context.Context, opts ...sv.Option) (signature.SignerVerifier, error) {
	return sv.New(ctx, append(slices.Clone(opts), sv.WithKEKProvider(KEKScheme, newAWSKEK))...)
}

// newAWSKEK returns a Tink AEAD encryption key from AWS KMS.
func newAWSKEK(ctx context.Context, kmsKey string) (tink.AEAD, error) {
	awsClient, err := awskms.NewClientWithOptions(ctx, kmsKey)
	if err != nil {
		return nil, err
	}
	registry.RegisterKMSClient(awsClient)
	return awsClient.GetAEAD(kmsKey)
}

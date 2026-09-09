/*
Copyright 2025 The Sigstore Authors

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

package signerverifier

import (
	"context"
	"errors"
	"slices"
	"testing"

	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// awsKMSScheme is the reference scheme registered by the AWS KMS provider. It is
// written literally rather than imported so that this package's own import is what
// registers it.
const awsKMSScheme = "awskms://"

// TestAWSKMSProviderRegistered guards against the import of the AWS KMS provider
// being dropped, which would silently disable awskms:// keys.
func TestAWSKMSProviderRegistered(t *testing.T) {
	if !slices.Contains(kms.SupportedProviders(), awsKMSScheme) {
		t.Errorf("expected %s to be a supported KMS provider, got %v", awsKMSScheme, kms.SupportedProviders())
	}
}

// TestAWSKEKProviderWired guards against New dropping its KEK provider injection,
// which would silently disable aws-kms:// Tink key encryption keys. An aws-kms:// URI
// must get past prefix resolution, so the error must be anything other than an
// unsupported key type.
//
// The ARN carries its own region and the AWS SDK resolves credentials lazily, so the
// client is built locally. IMDS is disabled and static credentials are supplied so
// that the test cannot fall back to the instance metadata endpoint.
func TestAWSKEKProviderWired(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	_, err := New(context.Background(),
		sv.WithTink(KEKScheme+"arn:aws:kms:us-east-1:111122223333:key/abcd", "keyset.json.enc"))
	if err == nil {
		t.Fatal("expected an error, since the keyset does not exist")
	}
	if err.Error() == "unsupported KMS key type" {
		t.Errorf("expected %s to be resolved by the injected provider, got %q", KEKScheme, err.Error())
	}
}

// TestAWSKEKProviderRejectsGCPURI pins the per-cloud boundary: an AWS-configured
// binary must not resolve a GCP key encryption key. The keyset path is non-empty so
// that the unset guard does not mask the assertion, and the URI is rejected before
// the file is opened or AWS is contacted.
func TestAWSKEKProviderRejectsGCPURI(t *testing.T) {
	_, err := New(context.Background(), sv.WithTink("gcp-kms://project/key", "keyset.json.enc"))
	if err == nil {
		t.Fatal("expected an error for a GCP key encryption key URI")
	}
	if err.Error() != "unsupported KMS key type" {
		t.Errorf("expected \"unsupported KMS key type\", got %q", err.Error())
	}
}

// TestAWSKEKProviderNotOverridable pins that a caller cannot substitute another
// cloud's provider, which the registry-free wiring depends on.
func TestAWSKEKProviderNotOverridable(t *testing.T) {
	var called string
	caller := func(_ context.Context, kmsKey string) (tink.AEAD, error) {
		called = kmsKey
		return nil, errors.New("caller-supplied provider reached")
	}
	_, err := New(context.Background(),
		sv.WithTink("gcp-kms://project/key", "keyset.json.enc"),
		sv.WithKEKProvider("gcp-kms://", caller))
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "unsupported KMS key type" {
		t.Errorf("expected \"unsupported KMS key type\", got %q", err.Error())
	}
	if called != "" {
		t.Errorf("expected the caller-supplied provider to be ignored, got %q", called)
	}
}

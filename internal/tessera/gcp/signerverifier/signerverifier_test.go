/*
Copyright 2026 The Sigstore Authors

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
	"path/filepath"
	"slices"
	"testing"
	"time"

	sv "github.com/sigstore/rekor-tiles/v2/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// gcpKMSScheme is the reference scheme registered by the GCP KMS provider. It is
// written literally rather than imported so that this package's own import is what
// registers it.
const gcpKMSScheme = "gcpkms://"

// TestGCPKMSProviderRegistered guards against the import of the GCP KMS provider
// being dropped, which would silently disable gcpkms:// keys.
func TestGCPKMSProviderRegistered(t *testing.T) {
	if !slices.Contains(kms.SupportedProviders(), gcpKMSScheme) {
		t.Errorf("expected %s to be a supported KMS provider, got %v", gcpKMSScheme, kms.SupportedProviders())
	}
}

var errFakeKEK = errors.New("fake KEK provider reached")

// TestGCPKEKProviderWired guards against New dropping its KEK provider injection,
// which would silently disable gcp-kms:// Tink key encryption keys. A gcp-kms:// URI
// must get past prefix resolution, so the error must be anything other than an
// unsupported key type.
//
// Pointing application default credentials at a missing file makes credential
// discovery fail immediately, so the GCP client is never built and the test never
// probes the metadata server or reaches the network.
func TestGCPKEKProviderWired(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))
	_, err := New(context.Background(),
		sv.WithTink(KEKScheme+"projects/p/locations/l/keyRings/r/cryptoKeys/k", "keyset.json.enc"))
	if err == nil {
		t.Fatal("expected an error, since the credentials and keyset do not exist")
	}
	if err.Error() == "unsupported KMS key type" {
		t.Errorf("expected %s to be resolved by the injected provider, got %q", KEKScheme, err.Error())
	}
}

// TestGCPKEKProviderRejectsAWSURI pins the per-cloud boundary: a GCP-configured
// binary must not resolve an AWS key encryption key. The keyset path is non-empty so
// that the unset guard does not mask the assertion, and the URI is rejected before
// the file is opened or GCP is contacted.
func TestGCPKEKProviderRejectsAWSURI(t *testing.T) {
	_, err := New(context.Background(), sv.WithTink("aws-kms://project/key", "keyset.json.enc"))
	if err == nil {
		t.Fatal("expected an error for an AWS key encryption key URI")
	}
	if err.Error() != "unsupported KMS key type" {
		t.Errorf("expected \"unsupported KMS key type\", got %q", err.Error())
	}
}

// TestGCPKEKProviderNotOverridable pins that a caller cannot substitute another
// cloud's provider, which the registry-free wiring depends on.
func TestGCPKEKProviderNotOverridable(t *testing.T) {
	var called string
	caller := func(_ context.Context, kmsKey string) (tink.AEAD, error) {
		called = kmsKey
		return nil, errFakeKEK
	}
	_, err := New(context.Background(),
		sv.WithTink("aws-kms://project/key", "keyset.json.enc"),
		sv.WithKEKProvider("aws-kms://", caller))
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

func TestKMSRPCOptions(t *testing.T) {
	opts := KMSRPCOptions(3, 10*time.Second)
	if len(opts) != 1 {
		t.Fatalf("expected 1 RPC option, got %d", len(opts))
	}
	if opts[0] == nil {
		t.Error("expected a non-nil RPC option")
	}
}

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

package signerverifier

import (
	"context"
	"errors"
	"testing"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// errProviderReached is returned by the fake provider so that a test can assert the
// provider was invoked without supplying a real encrypted keyset.
var errProviderReached = errors.New("provider reached")

// fakeProvider records the key URI it was called with and then fails, which stops
// New before it reads a keyset from disk.
func fakeProvider(called *string) KEKProvider {
	return func(_ context.Context, kmsKey string) (tink.AEAD, error) {
		*called = kmsKey
		return nil, errProviderReached
	}
}

// TestWithKEKProviderResolvesMatchingPrefix pins that a URI carrying the injected
// prefix reaches the provider, and that the provider receives the full URI.
func TestWithKEKProviderResolvesMatchingPrefix(t *testing.T) {
	var called string
	_, err := New(context.Background(),
		WithTink("fake-kms://project/key", "keyset.json.enc"),
		WithKEKProvider("fake-kms://", fakeProvider(&called)))
	if !errors.Is(err, errProviderReached) {
		t.Fatalf("expected the provider to be invoked, got %v", err)
	}
	if called != "fake-kms://project/key" {
		t.Errorf("expected the provider to receive the full key URI, got %q", called)
	}
}

// TestWithKEKProviderRejectsForeignURI is the property that the per-cloud packages
// depend on: a URI outside the injected prefix must not reach the provider, so a
// binary wired for one cloud never hands a key URI to another cloud's SDK.
func TestWithKEKProviderRejectsForeignURI(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		provider KEKProvider
	}{
		{name: "non-matching prefix", prefix: "fake-kms://"},
		{name: "nil provider", prefix: "other-kms://", provider: nil},
		// An empty prefix would match every URI, so it must not act as a wildcard.
		{name: "empty prefix", prefix: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called string
			provider := tt.provider
			if tt.name != "nil provider" {
				provider = fakeProvider(&called)
			}
			_, err := New(context.Background(),
				WithTink("other-kms://project/key", "keyset.json.enc"),
				WithKEKProvider(tt.prefix, provider))
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Error() != "unsupported KMS key type" {
				t.Errorf("expected \"unsupported KMS key type\", got %q", err.Error())
			}
			if called != "" {
				t.Errorf("expected the provider not to be called, got %q", called)
			}
		})
	}
}

// TestWithKEKProviderUnsetGuardPrecedesResolution pins the error ordering inherited
// from the pre-refactor code: an unset keyset path is reported as such rather than
// as an unsupported key type.
func TestWithKEKProviderUnsetGuardPrecedesResolution(t *testing.T) {
	var called string
	_, err := New(context.Background(),
		WithTink("fake-kms://project/key", ""),
		WithKEKProvider("fake-kms://", fakeProvider(&called)))
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "key encryption key URI or keyset path unset" {
		t.Errorf("expected the unset guard to fire first, got %q", err.Error())
	}
	if called != "" {
		t.Errorf("expected the provider not to be called, got %q", called)
	}
}

// TestWithKEKProviderLastOptionWins pins that the option applied last is the one
// used, which is what lets a cloud package append its provider after the caller's
// options and stay authoritative.
func TestWithKEKProviderLastOptionWins(t *testing.T) {
	var first, second string
	_, err := New(context.Background(),
		WithTink("fake-kms://project/key", "keyset.json.enc"),
		WithKEKProvider("fake-kms://", fakeProvider(&first)),
		WithKEKProvider("fake-kms://", fakeProvider(&second)))
	if !errors.Is(err, errProviderReached) {
		t.Fatalf("expected the provider to be invoked, got %v", err)
	}
	if first != "" {
		t.Error("expected the earlier provider to be overridden")
	}
	if second == "" {
		t.Error("expected the last provider to be used")
	}
}

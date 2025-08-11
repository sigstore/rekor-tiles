//
// Copyright 2025 The Sigstore Authors.
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

package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	bundlePath      *string
	keyPath         *string
	trustedRootPath *string
)

func init() {
	bundlePath = flag.String("bundle", "", "path to bundle")
	keyPath = flag.String("key", "", "path to public key")
	trustedRootPath = flag.String("trusted-root", "", "path to trusted root")
	flag.Parse()
}

func main() {
	if flag.NArg() == 0 {
		log.Fatal("expected artifact to verify")
	}
	artifact, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := trustedMaterialForKey()
	if err != nil {
		log.Fatal(err)
	}

	verifierConfig := []verify.VerifierOption{
		verify.WithNoObserverTimestamps(),
		verify.WithTransparencyLog(1),
	}
	policy := verifyPolicy(artifact)

	b, err := getBundle()
	if err != nil {
		log.Fatal(err)
	}

	sev, err := verify.NewVerifier(trustedRoot, verifierConfig...)
	if err != nil {
		log.Fatal(err)
	}
	_, err = sev.Verify(b, policy)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("VERIFIED")
}

func trustedMaterialForKey() (root.TrustedMaterial, error) {
	pubPem, err := os.ReadFile(*keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pubPem))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	verifier, err := signature.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})

	trustedRoot, err := root.NewTrustedRootFromPath(*trustedRootPath)
	if err != nil {
		return nil, err
	}

	trustedMaterial := &verifyTrustedMaterial{
		TrustedMaterial: trustedRoot,
		keyTrustedMaterial: root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return key, nil
		}),
	}

	return trustedMaterial, nil
}

func getBundle() (*bundle.Bundle, error) {
	return bundle.LoadJSONFromPath(*bundlePath)
}

func verifyPolicy(artifact []byte) verify.PolicyBuilder {
	digest := sha256.Sum256(artifact)
	artifactPolicy := verify.WithArtifactDigest("sha256", digest[:])
	identityPolicies := []verify.PolicyOption{verify.WithKey()}
	return verify.NewPolicy(artifactPolicy, identityPolicies...)
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}

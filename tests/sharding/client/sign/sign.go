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
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

const tsaURL = "http://localhost:3004/api/v1/timestamp"

var (
	rekorURL          *string
	bundleOut         *string
	keyOut            *string
	trustedRootPath   *string
	signingConfigPath *string
)

func init() {
	rekorURL = flag.String("rekor-url", "", "rekor URL to bypass signing config discovery")
	bundleOut = flag.String("bundle-out", "", "output path to bundle")
	keyOut = flag.String("key-out", "", "output path to generated public key")
	trustedRootPath = flag.String("trusted-root", "", "path to trusted root")
	signingConfigPath = flag.String("signing-config", "", "path to signing config")
	flag.Parse()
}

func main() {
	if flag.NArg() == 0 {
		log.Fatal("expected artifact to sign")
	}
	artifact, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	content := &sign.PlainData{
		Data: artifact,
	}

	keypair, err := key()
	if err != nil {
		log.Fatal(err)
	}

	opts := sign.BundleOptions{}

	trustedRoot, err := trustedMaterialForKey(keypair)
	if err != nil {
		log.Fatal(err)
	}
	opts.TrustedRoot = trustedRoot

	signingConfig, err := signingConfig()
	if err != nil {
		log.Fatal(err)
	}

	rekorURLs, err := discoverRekorURLs(signingConfig, *rekorURL)
	if err != nil {
		log.Fatal(err)
	}
	err = setRekorOpts(&opts, rekorURLs)
	if err != nil {
		log.Fatal(err)
	}

	setTSAOpts(&opts)

	signedBundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(signedBundle)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(*bundleOut, bundleJSON, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SIGNED")
}

func key() (*sign.EphemeralKeypair, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}
	pubPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(*keyOut, []byte(pubPem), 0600)
	if err != nil {
		return nil, err
	}
	return keypair, nil
}

func trustedMaterialForKey(keypair *sign.EphemeralKeypair) (root.TrustedMaterial, error) {
	pubPem, err := keypair.GetPublicKeyPem()
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

func signingConfig() (*root.SigningConfig, error) {
	return root.NewSigningConfigFromPath(*signingConfigPath)
}

func discoverRekorURLs(signingConfig *root.SigningConfig, url string) ([]string, error) {
	fakeTime := os.Getenv("NOW")
	now := time.Now()
	if fakeTime != "" {
		var err error
		now, err = time.Parse(time.RFC3339, fakeTime)
		if err != nil {
			return nil, err
		}
	}
	if url != "" {
		return []string{url}, nil
	}
	return root.SelectServices(signingConfig.RekorLogURLs(), signingConfig.RekorLogURLsConfig(), []uint32{2}, now)
}

func setRekorOpts(opts *sign.BundleOptions, urls []string) error {
	for _, url := range urls {
		rekorOpts := &sign.RekorOptions{
			BaseURL: url,
			Timeout: time.Duration(90 * time.Second),
			Retries: 0,
			Version: 2,
		}
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
	}
	return nil
}

func setTSAOpts(opts *sign.BundleOptions) {
	tsaOpts := &sign.TimestampAuthorityOptions{
		URL:     tsaURL,
		Timeout: time.Duration(5 * time.Second),
		Retries: 0,
	}
	opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}

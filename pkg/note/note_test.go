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

package tessera

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/rekor-tiles/pkg/signer"
	"github.com/stretchr/testify/assert"
)

var (
	ed25519PrivKey = []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc
-----END PRIVATE KEY-----
`)
	ecdsaPrivKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOMZNOBbRU3CHBjZoc13R8HYNUoqsvce5UlOmRzlOZqUoAoGCCqGSM49
AwEHoUQDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4
NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END EC PRIVATE KEY-----
`)
	rsaPrivKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtJiSIDpTLnbadpWE
RqbhdFC+fUHJKli6GDhwzt7Ueip5l6Omi33kyxN5VGxAl99aOh+N5eVHgS2FGqcE
LY9FewIDAQABAkAXuHJ5CTAjyjinmrvlC8ZRIMnkad+iUEUhKUin41zFLtaNYbxB
hoUVqx9JXFuDp6d8Hum31H7Klt6Wte8KMCMBAiEA2JmJqeJKrfwZe5TJH1ka4gz6
UTfvtRL+wmzcY0l48sUCIQDVcm9Z0/FaIj3jcbrG1f09D3QNXwYHg21MRH9Gennb
PwIgG0NQIZL7JWUa7AQxQIHdsWBCzaBFyrvmVyCOqOyhjaUCIQCBc6Tq4uq20puc
TMaNfwzWMoAc9+uNNP1dyxEx6mfrOwIgSkgCl4Na91jDTHK2oEsUOJ11ITac+rvN
ixWmu2zRYIc=
-----END PRIVATE KEY-----
`)
)

func TestKeyHash(t *testing.T) {
	origin := "testkey"
	tests := []struct {
		name          string
		key           []byte
		expectedKeyID uint32
	}{
		{
			name:          "ed25519",
			key:           ed25519PrivKey,
			expectedKeyID: 3839787747, // sha256(origin || 0x0A || 0x01 || ed25519PrivKey)[:4]
		},
		{
			name:          "ecdsa",
			key:           ecdsaPrivKey,
			expectedKeyID: 2408765216, // sha256(ecdsaPrivKey.Public())[:4]
		},
		{
			name:          "rsa",
			key:           rsaPrivKey,
			expectedKeyID: 1044636651, // sha256(origin || 0x0A || 0xFF || "RSA-PKCS#1v1.5" || rsaPrivKey.Public())[:4]
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			td := t.TempDir()
			file := fmt.Sprintf("%s-priv.pem", test.name)
			keyFile := filepath.Join(td, file)
			if err := os.WriteFile(keyFile, []byte(test.key), 0644); err != nil {
				t.Fatal(err)
			}
			signer, err := signer.New(ctx, keyFile, "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			noteSigner, err := NewNoteSigner(ctx, origin, signer)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.expectedKeyID, noteSigner.KeyHash())
		})
	}
}

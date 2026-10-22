// Copyright 2026 The Sigstore Authors.
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

// Mock OIDC server, based on https://github.com/sigstore/scaffolding/blob/main/actions/setup-sigstore-env/fakeoidc/main.go
package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	rsaSigner   jose.Signer
	rsaJWK      jose.JSONWebKey
	mldsaSigner jose.Signer
	mldsaJWK    jose.JSONWebKey
)

type config struct {
	Issuer               string   `json:"issuer"`
	JWKSURI              string   `json:"jwks_uri"`
	SupportedSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

type customClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func init() {
	rsaPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	rsaJWK = jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       rsaPK,
		KeyID:     "rsa-key",
	}
	rsaSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       rsaJWK.Key,
	}, (&jose.SignerOptions{}).WithHeader("kid", rsaJWK.KeyID))
	if err != nil {
		log.Fatal(err)
	}

	mldsaPK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		log.Fatal(err)
	}
	mldsaJWK = jose.JSONWebKey{
		Algorithm: string(jose.ML_DSA_44),
		Key:       mldsaPK,
		KeyID:     "mldsa-key",
	}
	mldsaSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ML_DSA_44,
		Key:       mldsaJWK.Key,
	}, (&jose.SignerOptions{}).WithHeader("kid", mldsaJWK.KeyID))
	if err != nil {
		log.Fatal(err)
	}
}

func token(w http.ResponseWriter, r *http.Request) {
	log.Print("handling /token")
	// Hardcode the issuer unless a different issuer is requested.
	// This is a workaround for supporting this environment on macOS.
	issuer := r.URL.Query().Get("issuer")
	if issuer == "" {
		issuer = "http://fakeoidc:8080"
	}

	signer := mldsaSigner
	if r.URL.Query().Get("alg") == string(jose.RS256) {
		signer = rsaSigner
	}

	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "foo@bar.com",
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{
		Email:         "foo@bar.com",
		EmailVerified: true,
	}).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(tok))
}

func keys(w http.ResponseWriter, _ *http.Request) {
	log.Print("handling /keys")
	jwks, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			rsaJWK.Public(),
			mldsaJWK.Public(),
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-type", "application/json")
	_, _ = w.Write(jwks)
}

func wellKnown(w http.ResponseWriter, r *http.Request) {
	log.Print("handling /.well-known/openid-configuration")
	issuer := fmt.Sprintf("http://%s", r.Host)
	cfg, err := json.Marshal(config{
		Issuer:  issuer,
		JWKSURI: issuer + "/keys",
		SupportedSigningAlgs: []string{
			string(jose.RS256),
			string(jose.ML_DSA_44),
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-type", "application/json")
	_, _ = w.Write(cfg)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", token)
	mux.HandleFunc("/keys", keys)
	mux.HandleFunc("/.well-known/openid-configuration", wellKnown)
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

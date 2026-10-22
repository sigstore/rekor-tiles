// Copyright 2026 The Sigstore Authors
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

package identity_v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	fulciocert "github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const defaultOIDCDiscoveryTimeout = 10 * time.Second

// allOIDCSigningAlgs lists the asymmetric JOSE signature algorithms supported
// for OIDC ID token verification, including ML-DSA (RFC 9964).
var allOIDCSigningAlgs = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.EdDSA,
	jose.ML_DSA_44,
	jose.ML_DSA_65,
	jose.ML_DSA_87,
}

var supportedOIDCSigningAlgs = map[string]bool{}

func init() {
	for _, alg := range allOIDCSigningAlgs {
		supportedOIDCSigningAlgs[string(alg)] = true
	}
	identity.Authorize = authorizeOIDCToken
}

type verifierCacheKey struct {
	fc        *config.FulcioConfig
	issuerURL string
}

type verifierWithConfig struct {
	verifier *oidc.IDTokenVerifier
	config   *oidc.Config
}

var (
	verifierCacheMu sync.Mutex
	verifierCache   = map[verifierCacheKey][]*verifierWithConfig{}
)

func authorizeOIDCToken(ctx context.Context, token string, opts ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
	issuer, err := extractIssuerURL(token)
	if err != nil {
		return nil, err
	}

	fc := config.FromContext(ctx)
	if fc == nil {
		return nil, errors.New("oidc config must be provided")
	}

	verifier, ok := getOIDCVerifier(ctx, fc, issuer, opts...)
	if !ok {
		return nil, fmt.Errorf("unsupported issuer: %s", issuer)
	}
	return verifier.Verify(ctx, token)
}

func extractIssuerURL(token string) (string, error) {
	if strings.Count(token, ".") != 2 {
		return "", fmt.Errorf("oidc: malformed jwt, token must have 3 parts")
	}

	parts := strings.SplitN(token, ".", 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}

	var payload struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	return payload.Issuer, nil
}

func getOIDCVerifier(ctx context.Context, fc *config.FulcioConfig, issuerURL string, opts ...config.InsecureOIDCConfigOption) (*oidc.IDTokenVerifier, bool) {
	iss, ok := fc.GetIssuer(issuerURL)
	if !ok {
		return nil, false
	}

	cfg := &oidc.Config{ClientID: iss.ClientID}
	for _, o := range opts {
		o(cfg)
	}

	key := verifierCacheKey{fc: fc, issuerURL: issuerURL}
	verifierCacheMu.Lock()
	if entries, ok := verifierCache[key]; ok {
		for _, entry := range entries {
			if reflect.DeepEqual(entry.config, cfg) {
				verifierCacheMu.Unlock()
				return entry.verifier, true
			}
		}
	}
	verifierCacheMu.Unlock()

	client, err := httpClientForIssuer(iss)
	if err != nil {
		return nil, false
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, defaultOIDCDiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(oidc.ClientContext(discoveryCtx, client), issuerURL)
	if err != nil {
		return nil, false
	}

	var discovery struct {
		JWKSURL    string   `json:"jwks_uri"`
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&discovery); err != nil || discovery.JWKSURL == "" {
		return nil, false
	}

	var algs []string
	for _, a := range discovery.Algorithms {
		if supportedOIDCSigningAlgs[a] {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	}

	verifierCfg := *cfg
	if len(verifierCfg.SupportedSigningAlgs) == 0 {
		verifierCfg.SupportedSigningAlgs = algs
	}

	ks := &remoteKeySet{
		jwksURL: discovery.JWKSURL,
		client:  client,
	}
	v := oidc.NewVerifier(issuerURL, ks, &verifierCfg)

	verifierCacheMu.Lock()
	verifierCache[key] = append(verifierCache[key], &verifierWithConfig{
		verifier: v,
		config:   cfg,
	})
	verifierCacheMu.Unlock()

	return v, true
}

func httpClientForIssuer(iss config.OIDCIssuer) (*http.Client, error) {
	transport := http.DefaultTransport
	if iss.CACert != "" {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		if ok := rootCAs.AppendCertsFromPEM([]byte(iss.CACert)); !ok {
			return nil, fmt.Errorf("failed to append custom CA cert for issuer URL %q", iss.IssuerURL)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		}
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("oidc: redirect to different host %q blocked", req.URL.Host)
			}
			return nil
		},
	}, nil
}

// remoteKeySet implements oidc.KeySet while supporting ML-DSA (AKP) JWKs via go-jose.
type remoteKeySet struct {
	jwksURL    string
	client     *http.Client
	mu         sync.RWMutex
	cachedKeys []jose.JSONWebKey
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, allOIDCSigningAlgs)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}

	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	r.mu.RLock()
	cached := r.cachedKeys
	r.mu.RUnlock()

	for _, key := range cached {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	keys, err := r.updateKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys: %w", err)
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("failed to verify id token signature")
}

func (r *remoteKeySet) updateKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: get keys failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode keys: %w", err)
	}

	var keys []jose.JSONWebKey
	for _, rawKey := range raw.Keys {
		var metadata struct {
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(rawKey, &metadata); err != nil {
			return nil, fmt.Errorf("oidc: failed to decode key metadata: %w", err)
		}
		if metadata.Alg != "" && !supportedOIDCSigningAlgs[metadata.Alg] {
			continue
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(rawKey, &jwk); err != nil {
			if errors.Is(err, jose.ErrUnsupportedKeyType) {
				continue
			}
			return nil, fmt.Errorf("oidc: failed to decode key: %w", err)
		}
		keys = append(keys, jwk)
	}

	r.mu.Lock()
	r.cachedKeys = keys
	r.mu.Unlock()

	return keys, nil
}

// extractOIDCClaims uses Fulcio's libraries to verify an OIDC token
// and returns the issuer and all claims.
func extractOIDCClaims(ctx context.Context, tokenString string, pool identity.IssuerPool) (string, map[string]string, error) {
	if config.FromContext(ctx) == nil {
		return "", nil, errors.New("oidc config must be provided")
	}
	principal, err := pool.Authenticate(ctx, tokenString)
	if err != nil {
		return "", nil, fmt.Errorf("failed to authenticate token using fulcio: %w", err)
	}

	cert := &x509.Certificate{}
	if err := principal.Embed(ctx, cert); err != nil {
		return "", nil, fmt.Errorf("failed to embed claims: %w", err)
	}

	exts, err := fulciocert.ParseExtensions(cert.ExtraExtensions)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse extensions: %w", err)
	}

	claims := make(map[string]string)
	val := reflect.ValueOf(exts)
	typ := reflect.TypeFor[fulciocert.Extensions]()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		yamlTag := field.Tag.Get("yaml")
		if yamlTag == "" {
			continue
		}

		// Skip deprecated Fulcio v1 github-workflow-* OIDs.
		key, _, _ := strings.Cut(yamlTag, ",")
		if key == "" || strings.HasPrefix(key, "github-workflow-") {
			continue
		}

		fieldVal := val.Field(i).String()
		if fieldVal != "" {
			claims[key] = fieldVal
		}
	}

	cert.Extensions = cert.ExtraExtensions
	sans := cryptoutils.GetSubjectAlternateNames(cert)
	if len(sans) == 0 {
		return "", nil, fmt.Errorf("certificate does not contain a subject alternate name")
	}
	claims["identity"] = sans[0]
	claims["issuer"] = exts.Issuer

	for k, v := range claims {
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return "", nil, fmt.Errorf("claim %q contains invalid newline character", k)
		}
	}

	return exts.Issuer, claims, nil
}

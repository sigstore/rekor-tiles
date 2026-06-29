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

package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	fulciocert "github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/server"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// extractOIDCClaims uses Fulcio's libraries to verify an OIDC token
// and returns the issuer and all claims.
func extractOIDCClaims(ctx context.Context, tokenString string, cfg *config.FulcioConfig) (string, map[string]string, error) {
	if cfg == nil {
		cfg = config.DefaultConfig
	}
	ctx = config.With(ctx, cfg)
	pool := server.NewIssuerPool(cfg)
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
		yamlTag := field.Tag.Get("yaml")
		if yamlTag == "" {
			continue
		}

		key, _, _ := strings.Cut(yamlTag, ",")
		if key == "" || strings.HasPrefix(key, "github-workflow-") {
			continue
		}

		fieldVal := val.Field(i).String()
		if fieldVal != "" {
			claims[key] = fieldVal
		}
	}

	sans := cryptoutils.GetSubjectAlternateNames(cert)
	if len(sans) == 0 {
		return "", nil, fmt.Errorf("certificate does not contain a subject alternate name")
	}
	claims["san"] = sans[0]

	return exts.Issuer, claims, nil
}

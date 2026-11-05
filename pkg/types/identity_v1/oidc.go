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
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strings"

	fulciocert "github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

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

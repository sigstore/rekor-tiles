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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestExtractOIDCClaims_InvalidToken(t *testing.T) {
	ctx := context.Background()

	// 1. Empty token
	_, _, err := extractOIDCClaims(ctx, "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate token")

	// 2. Malformed token (not 3 parts)
	_, _, err = extractOIDCClaims(ctx, "header.payload", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate token")

	// 3. Invalid signature / issuer
	// Header: {"alg":"RS256"} -> eyJhbGciOiJSUzI1NiJ9
	// Payload: {"iss":"https://token.actions.githubusercontent.com","sub":"repo:foo/bar:ref:refs/heads/main"} -> eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwic3ViIjoicmVwbzpmb28vYmFyOnJlZjpyZWZzL2hlYWRzL21haW4ifQ==
	invalidToken := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwic3ViIjoicmVwbzpmb28vYmFyOnJlZjpyZWZzL2hlYWRzL21haW4ifQ==.invalidsignature"
	_, _, err = extractOIDCClaims(ctx, invalidToken, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate token")
}

type mockOIDC struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
}

func newMockOIDC(t *testing.T) *mockOIDC {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	m := &mockOIDC{priv: priv, pub: &priv.PublicKey}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":   m.server.URL,
			"jwks_uri": m.server.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{Key: m.pub, KeyID: "test-key", Algorithm: string(jose.RS256)}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockOIDC) token(t *testing.T, sub, email string) string {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: m.priv}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	assert.NoError(t, err)

	cl := struct {
		jwt.Claims
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}{
		Claims: jwt.Claims{
			Issuer:   m.server.URL,
			Subject:  sub,
			Audience: []string{"sigstore"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Email:         email,
		EmailVerified: true,
	}

	raw, err := jwt.Signed(signer).Claims(cl).Serialize()
	assert.NoError(t, err)
	return raw
}

func TestExtractOIDCClaims_ValidToken(t *testing.T) {
	ctx := context.Background()

	m := newMockOIDC(t)
	defer m.server.Close()

	cfgJSON := fmt.Sprintf(`{
		"OIDCIssuers": {
			"%s": {
				"IssuerURL": "%s",
				"ClientID":  "sigstore",
				"Type":      "email"
			}
		}
	}`, m.server.URL, m.server.URL)

	tempFile := t.TempDir() + "/oidc-config.json"
	assert.NoError(t, os.WriteFile(tempFile, []byte(cfgJSON), 0644))

	cfg, err := config.Load(tempFile)
	assert.NoError(t, err)

	tok := m.token(t, "test-sub", "foo@example.com")

	iss, claims, err := extractOIDCClaims(ctx, tok, cfg)
	assert.NoError(t, err)
	assert.Equal(t, m.server.URL, iss)
	assert.Equal(t, m.server.URL, claims["issuer"])
	assert.Equal(t, "foo@example.com", claims["identity"])
	assert.Equal(t, "test-sub", claims["subject"])
}

// githubClaims holds the additional JWT claims for GitHub OIDC tokens
type githubClaims struct {
	JobWorkflowRef       string `json:"job_workflow_ref"`
	Sha                  string `json:"sha"`
	EventName            string `json:"event_name"`
	Repository           string `json:"repository"`
	Workflow             string `json:"workflow"`
	Ref                  string `json:"ref"`
	JobWorkflowSha       string `json:"job_workflow_sha"`
	RunnerEnvironment    string `json:"runner_environment"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	WorkflowRef          string `json:"workflow_ref"`
	WorkflowSha          string `json:"workflow_sha"`
	RunID                string `json:"run_id"`
	RunAttempt           string `json:"run_attempt"`
	Environment          string `json:"environment"`
}

func (m *mockOIDC) githubToken(t *testing.T, sub string, claims *githubClaims) string {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: m.priv}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	assert.NoError(t, err)

	cl := struct {
		jwt.Claims
		*githubClaims
	}{
		Claims: jwt.Claims{
			Issuer:   m.server.URL,
			Subject:  sub,
			Audience: []string{"sigstore"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		githubClaims: claims,
	}

	raw, err := jwt.Signed(signer).Claims(cl).Serialize()
	assert.NoError(t, err)
	return raw
}

func TestExtractOIDCClaims_GitHubToken(t *testing.T) {
	ctx := context.Background()

	m := newMockOIDC(t)
	defer m.server.Close()

	cfgJSON := fmt.Sprintf(`{
		"OIDCIssuers": {
			"%s": {
				"IssuerURL": "%s",
				"ClientID":  "sigstore",
				"Type":      "github-workflow"
			}
		}
	}`, m.server.URL, m.server.URL)

	tempFile := t.TempDir() + "/oidc-config-github.json"
	assert.NoError(t, os.WriteFile(tempFile, []byte(cfgJSON), 0644))

	cfg, err := config.Load(tempFile)
	assert.NoError(t, err)

	ghClaims := &githubClaims{
		JobWorkflowRef:       "job/workflow/ref",
		Sha:                  "sha",
		EventName:            "trigger",
		Repository:           "sigstore/fulcio",
		Workflow:             "workflow",
		Ref:                  "refs/heads/main",
		JobWorkflowSha:       "example-sha",
		RunnerEnvironment:    "github-hosted",
		RepositoryID:         "12345",
		RepositoryOwner:      "username",
		RepositoryOwnerID:    "345",
		RepositoryVisibility: "public",
		WorkflowRef:          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
		WorkflowSha:          "example-sha-other",
		RunID:                "42",
		RunAttempt:           "1",
	}

	tok := m.githubToken(t, "repo:sigstore/fulcio:ref:refs/heads/main", ghClaims)

	iss, claims, err := extractOIDCClaims(ctx, tok, cfg)
	assert.NoError(t, err)

	assert.Equal(t, m.server.URL, iss)
	assert.Equal(t, "https://github.com/job/workflow/ref", claims["build-signer-uri"])
	assert.Equal(t, "https://github.com/sigstore/fulcio", claims["source-repository-uri"])
	assert.Equal(t, "sha", claims["source-repository-digest"])
	assert.Equal(t, "https://github.com/sigstore/fulcio/actions/runs/42/attempts/1", claims["run-invocation-uri"])
	assert.Equal(t, "example-sha", claims["build-signer-digest"])
	assert.Equal(t, "345", claims["source-repository-owner-identifier"])
	assert.Equal(t, "example-sha-other", claims["build-config-digest"])
	assert.Equal(t, "public", claims["source-repository-visibility-at-signing"])
	assert.Equal(t, "https://github.com/job/workflow/ref", claims["identity"])
	assert.Equal(t, "refs/heads/main", claims["source-repository-ref"])
	assert.Equal(t, "12345", claims["source-repository-identifier"])
	assert.Equal(t, "https://github.com/username", claims["source-repository-owner-uri"])
	assert.Equal(t, "trigger", claims["build-trigger"])
	assert.Equal(t, "repo:sigstore/fulcio:ref:refs/heads/main", claims["subject"])
	assert.Equal(t, "github-hosted", claims["runner-environment"])
	assert.Equal(t, "https://github.com/sigstore/other/.github/workflows/foo.yaml@refs/heads/main", claims["build-config-uri"])
	assert.Equal(t, m.server.URL, claims["issuer"])
	assert.Len(t, claims, 17)
}

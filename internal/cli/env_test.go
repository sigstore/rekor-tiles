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

package cli

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestEnvVarName(t *testing.T) {
	for flag, want := range map[string]string{
		"aws-mysql-dsn":    "REKOR_AWS_MYSQL_DSN",
		"gcp-cloudsql-dsn": "REKOR_GCP_CLOUDSQL_DSN",
		"hostname":         "REKOR_HOSTNAME",
	} {
		if got := EnvVarName(flag); got != want {
			t.Errorf("EnvVarName(%q) = %q, want %q", flag, got, want)
		}
	}
}

// newServeCmd returns a command with the shared flags plus a DSN flag, with
// args parsed and the flags bound to a fresh viper instance.
func newServeCmd(t *testing.T, args ...string) (*cobra.Command, *viper.Viper) {
	t.Helper()
	cmd := &cobra.Command{Use: "serve"}
	if err := Initialize(cmd); err != nil {
		t.Fatalf("unexpected error initializing flags: %v", err)
	}
	cmd.Flags().String("aws-mysql-dsn", "", "MySQL DSN")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}
	v := viper.New()
	if err := v.BindPFlags(cmd.Flags()); err != nil {
		t.Fatalf("unexpected error binding flags: %v", err)
	}
	return cmd, v
}

func TestSetFlagsFromEnv(t *testing.T) {
	t.Setenv("REKOR_AWS_MYSQL_DSN", "user:pass@tcp(db:3306)/sequencer")
	t.Setenv("REKOR_HTTP_PORT", "8080")
	t.Setenv("REKOR_SERVER_TIMEOUT", "5s")
	t.Setenv("REKOR_READ_ONLY", "true")
	t.Setenv("REKOR_CLIENT_SIGNING_ALGORITHMS", "ed25519,ecdsa-sha2-256-nistp256")
	// Unprefixed variables must not be picked up.
	t.Setenv("HOSTNAME", "from-unprefixed-env")
	t.Setenv("GRPC_PORT", "9999")
	// Empty variables are ignored, so the flag keeps its default.
	t.Setenv("REKOR_LOG_LEVEL", "")

	cmd, v := newServeCmd(t)
	defaultHostname, _ := cmd.Flags().GetString("hostname")
	if err := SetFlagsFromEnv(cmd.Flags()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := v.GetString("aws-mysql-dsn"); got != "user:pass@tcp(db:3306)/sequencer" {
		t.Errorf("aws-mysql-dsn = %q", got)
	}
	if got := v.GetInt("http-port"); got != 8080 {
		t.Errorf("http-port = %d, want 8080", got)
	}
	if got := v.GetDuration("server-timeout"); got != 5*time.Second {
		t.Errorf("server-timeout = %v, want 5s", got)
	}
	if !v.GetBool("read-only") {
		t.Error("read-only = false, want true")
	}
	if got, want := v.GetStringSlice("client-signing-algorithms"), []string{"ed25519", "ecdsa-sha2-256-nistp256"}; !slices.Equal(got, want) {
		t.Errorf("client-signing-algorithms = %q, want %q", got, want)
	}
	if got := v.GetString("hostname"); got != defaultHostname {
		t.Errorf("hostname = %q, want default %q", got, defaultHostname)
	}
	if got := v.GetInt("grpc-port"); got != 3001 {
		t.Errorf("grpc-port = %d, want default 3001", got)
	}
	if got := v.GetString("log-level"); got != "info" {
		t.Errorf("log-level = %q, want default info", got)
	}
}

func TestSetFlagsFromEnvCommandLineTakesPrecedence(t *testing.T) {
	t.Setenv("REKOR_AWS_MYSQL_DSN", "from-env")
	t.Setenv("REKOR_HTTP_PORT", "8080")

	cmd, v := newServeCmd(t, "--aws-mysql-dsn=from-flag")
	if err := SetFlagsFromEnv(cmd.Flags()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := v.GetString("aws-mysql-dsn"); got != "from-flag" {
		t.Errorf("aws-mysql-dsn = %q, want from-flag", got)
	}
	if got := v.GetInt("http-port"); got != 8080 {
		t.Errorf("http-port = %d, want 8080", got)
	}
}

func TestSetFlagsFromEnvInvalidValue(t *testing.T) {
	t.Setenv("REKOR_HTTP_PORT", "not-a-port")
	t.Setenv("REKOR_SERVER_TIMEOUT", "forever")

	cmd, _ := newServeCmd(t)
	err := SetFlagsFromEnv(cmd.Flags())
	if err == nil {
		t.Fatal("expected an error for invalid values")
	}
	for _, name := range []string{"REKOR_HTTP_PORT", "REKOR_SERVER_TIMEOUT"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("expected error to mention %s, got: %v", name, err)
		}
	}
}

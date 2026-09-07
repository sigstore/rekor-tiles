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
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestInitializeFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "serve"}
	if err := Initialize(cmd); err != nil {
		t.Fatalf("unexpected error initializing flags: %v", err)
	}

	if cmd.Flags().Lookup("server-timeout") == nil {
		t.Error("expected server-timeout flag to be registered")
	}
	if cmd.Flags().Lookup("server-idle-timeout") == nil {
		t.Error("expected server-idle-timeout flag to be registered")
	}
}

func TestServerIdleTimeout(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected time.Duration
	}{
		{
			name:     "default timeout",
			expected: 60 * time.Second,
		},
		{
			name:     "server-idle-timeout flag",
			args:     []string{"--server-idle-timeout=15s"},
			expected: 15 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			cmd := &cobra.Command{Use: "serve"}
			if err := Initialize(cmd); err != nil {
				t.Fatalf("unexpected error initializing flags: %v", err)
			}
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				t.Fatalf("unexpected error binding flags: %v", err)
			}
			if len(tc.args) > 0 {
				if err := cmd.ParseFlags(tc.args); err != nil {
					t.Fatalf("failed parsing flags: %v", err)
				}
			}

			actual := viper.GetDuration("server-idle-timeout")
			if actual != tc.expected {
				t.Errorf("expected server-idle-timeout to be %v, got %v", tc.expected, actual)
			}
		})
	}
}

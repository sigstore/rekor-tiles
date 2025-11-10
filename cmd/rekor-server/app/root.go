//
// Copyright 2025 The Sigstore Authors.
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

package app

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(backend BackendConfig) {
	// Configure root command based on backend
	rootCmd.Use = "rekor-server-" + backend.Name()
	rootCmd.Short = "Rekor signature transparency log server (" + backend.Name() + ")"
	rootCmd.Long = `Rekor fulfills the signature transparency role of sigstore's software
	signing infrastructure. This is the ` + backend.Name() + `-specific binary that only includes
	` + backend.Description() + ` dependencies.`

	// Initialize the serve command with the backend
	initServeCmd(backend)

	if err := rootCmd.Execute(); err != nil {
		slog.Error("failed to execute root command", "error", err)
		os.Exit(1)
	}
}

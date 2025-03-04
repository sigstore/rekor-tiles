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
	"context"
	"log/slog"

	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor-tiles/pkg/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the Rekor server",
	Long:  "start the Rekor server",
	Run: func(_ *cobra.Command, _ []string) {
		versionInfo := version.GetVersionInfo()
		versionInfoStr, err := versionInfo.JSONString()
		if err != nil {
			versionInfoStr = versionInfo.String()
		}
		slog.Info("starting rekor-server", "version", versionInfoStr)

		// TODO: read values from cmdline
		server.Serve(
			context.Background(),
			// TODO: use defaults for now, but really use commandline
			server.NewHTTPConfig(),
			server.NewGRPCConfig(),
			&server.Server{},
		)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

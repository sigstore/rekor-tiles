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
	"fmt"
	"log/slog"
	"os"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.32.0"
	"sigs.k8s.io/release-utils/version"
)

// initOTel initializes Open Telemetry support for metrics.
// Returns a shutdown function which should be called before exiting the process.
func initOTel(ctx context.Context) func(context.Context) {
	appVersion := version.GetVersionInfo()
	options := []resource.Option{
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(), // unpacks OTEL_RESOURCE_ATTRIBUTES
		resource.WithAttributes(
			semconv.ServiceName("rekor-tiles"),
			semconv.ServiceVersion(appVersion.String()),
		),
	}
	if viper.GetString("gcp-bucket") != "" || viper.GetString("gcp-spanner") != "" {
		options = append(options, resource.WithDetectors(gcp.NewDetector()))
	}
	resources, err := resource.New(ctx,
		options...,
	)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to create OTel resources: %v", err))
		os.Exit(1)
	}

	me, err := mexporter.New()
	if err != nil {
		slog.Warn("could not create metric exporter, likely not running in GCP")
		return func(context.Context) {}
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(me)),
		sdkmetric.WithResource(resources),
	)
	otel.SetMeterProvider(mp)

	shutdown := func(ctx context.Context) {
		if err := mp.Shutdown(ctx); err != nil {
			slog.Error(fmt.Sprintf("error shutting down meter provider: %v", err))
		}
	}

	slog.Info("Initialized OTel metric exporter for GCP")

	return shutdown
}

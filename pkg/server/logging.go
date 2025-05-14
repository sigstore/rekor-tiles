// Copyright 2025 The Sigstore Authors
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

package server

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
)

func interceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		switch msg {
		case "request received", "request sent", "response received", "response sent", "finished call":
			for i := range len(fields) - 1 {
				if key, ok := fields[i].(string); ok && key == "grpc.service" {
					if value, ok := fields[i+1].(string); ok && value == "grpc.health.v1.Health" {
						// skip logging anything for health check
						return
					}
				}
			}
		}
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func loggingOpts(level slog.Level, requestResponseLogging bool) []logging.Option {
	events := []logging.LoggableEvent{}
	if level == slog.LevelDebug {
		events = append(events, logging.FinishCall)
		if requestResponseLogging {
			events = append(events, logging.PayloadReceived, logging.PayloadSent)
		}
	}
	return []logging.Option{logging.WithLogOnEvents(events...)}
}

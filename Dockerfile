#
# Copyright 2025 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.24.2@sha256:18a1f2d1e1d3c49f27c904e9182375169615c65852ace724987929b910195b2c AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/

ARG SERVER_LDFLAGS
RUN go build -ldflags "${SERVER_LDFLAGS}" ./cmd/rekor-server
RUN CGO_ENABLED=0 go build -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server

# Multi-Stage production build
FROM golang:1.24.2@sha256:18a1f2d1e1d3c49f27c904e9182375169615c65852ace724987929b910195b2c AS deploy

# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server

# Set the binary as the entrypoint of the container
CMD ["rekor-server", "serve"]

# debug compile options & debugger
FROM deploy AS debug
# dlv v1.24.1
RUN go install github.com/go-delve/delve/cmd/dlv@fc6a439f2206c796bb20f56f37f8e10eb26cb158

# overwrite server and include debugger
COPY --from=builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server

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

FROM --platform=$BUILDPLATFORM golang:1.24.4@sha256:10c131810f80a4802c49cab0961bbe18a16f4bb2fb99ef16deaa23e4246fc817 AS builder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/
ADD ./internal/ $APP_ROOT/src/internal/

ARG SERVER_LDFLAGS
# Build server for deployment
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -ldflags "${SERVER_LDFLAGS}" ./cmd/rekor-server
# Build server for debugger
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server

# Multi-stage deployment build
FROM golang:1.24.4@sha256:10c131810f80a4802c49cab0961bbe18a16f4bb2fb99ef16deaa23e4246fc817 AS deploy
# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server
# Set the binary as the entrypoint of the container
CMD ["rekor-server", "serve"]

# Cross-compile dlv for the debug stage
FROM builder AS dlvbuilder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT
# Create a directory where 'go install' may install the cross-compiled binary,
# if the build and target platform differ.
RUN mkdir -p /opt/app-root/bin/${TARGETOS}_${TARGETARCH}
# dlv v1.24.2
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/go-delve/delve/cmd/dlv@f0cc62bfcaa18b9f2cd01cebd818fad537ee93ec

# Multi-stage debugger build
FROM deploy AS debug
ARG TARGETOS
ARG TARGETARCH
# Copy dlv binary, either from bin/ when the build and target platform are the same, or
# from bin/TARGETOS_TARGETARCH when the platforms are different.
COPY --from=dlvbuilder /opt/app-root/bin/dlv* /opt/app-root/bin/${TARGETOS}_${TARGETARCH}/dlv* /usr/local/bin/
# Overwrite server binary
COPY --from=builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server

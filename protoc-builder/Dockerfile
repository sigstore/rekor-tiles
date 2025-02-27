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

# syntax=docker/dockerfile-upstream:master
# This container grabs the protoc compiler and the googleapi includes
# /protobuf will contain the extracted protoc
# /googleapis will contain the various googleapis proto imports one might need
FROM debian:bullseye-slim@sha256:6344a6747740d465bff88e833e43ef881a8c4dd51950dba5b30664c93f74cbef AS protoc-builder

# Create output directories
RUN mkdir /protobuf /googleapis
# Install needed utilities
RUN apt-get update && apt-get install -y unzip git

# Set up user and group to match host we're building the container on
ARG UID

RUN adduser --uid ${UID} --disabled-password myuser

# Set permissions on the output directories so the user can write to them
RUN chown myuser /protobuf /googleapis

# Switch to user to execute the remaining commands
USER myuser

# Download specific release of protoc
# TODO: add dependabot-like feature to check for release updates
ARG PROTOC_VERSION
ARG PROTOC_VERSION_TAG
ARG PROTOC_CHECKSUM

ADD --chown=myuser https://github.com/protocolbuffers/protobuf/releases/download/${PROTOC_VERSION_TAG}/protoc-${PROTOC_VERSION}-linux-x86_64.zip /tmp/protoc.zip
RUN unzip -d /protobuf /tmp/protoc.zip
RUN chmod 755 /protobuf/bin/protoc

# fetch specific commit of googleapis
ARG GOOGLEAPIS_COMMIT
RUN git clone --filter=blob:none --no-checkout --depth=1 https://github.com/googleapis/googleapis.git /googleapis && \
    cd /googleapis && \
    git sparse-checkout set --no-cone '/**/*.proto' && \
    git checkout ${GOOGLEAPIS_COMMIT} && \
    rm -rf .git

FROM golang:1.24.0-alpine@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS go-builder

ADD go.* tools/

# the specific versions of these tools are in hack/go.mod so that Dependabot can bump them for updates
RUN cd tools && GOBIN=/go/tools go install tool

FROM gcr.io/distroless/static-debian12:nonroot@sha256:6ec5aa99dc335666e79dc64e4a6c8b89c33a543a1967f20d360922a80dd21f02

COPY --from=go-builder /go/tools/protoc-* /usr/local/bin/
COPY --from=protoc-builder /protobuf/bin/protoc /usr/local/bin/
COPY --from=protoc-builder /protobuf/include/google /opt/include/google
COPY --from=protoc-builder /googleapis /googleapis

ENTRYPOINT ["/usr/local/bin/protoc", "--plugin=protoc-gen-go=/usr/local/bin/protoc-gen-go", "--plugin=protoc-gen-go-grpc=/usr/local/bin/protoc-gen-go-grpc", "--plugin=protoc-gen-grpc-gateway=/usr/local/bin/protoc-gen-grpc-gateway", "--plugin=protoc-gen-openapiv2=/usr/local/bin/protoc-gen-openapiv2"]

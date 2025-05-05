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
FROM debian:bullseye-slim@sha256:fdd75562fdcde1039c2480a1ea1cd2cf03b18b6e4cb551cabb03bde66ade8a5d AS protoc-builder

# Create output directories
RUN mkdir /protobuf /googleapis /protobuf-specs
# Install needed utilities
RUN apt-get update && apt-get install -y unzip git

# Set up user and group to match host we're building the container on
ARG UID

RUN adduser --uid ${UID} --disabled-password myuser

# Set permissions on the output directories so the user can write to them
RUN chown myuser /protobuf /googleapis /protobuf-specs

# Switch to user to execute the remaining commands
USER myuser

# Download specific release of protoc
# TODO(#66): add dependabot-like feature to check for release updates
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

# fetch HEAD of protobuf-specs
# TODO(#66): adjust this to latest release like googleapis
ARG PROTOBUF_SPECS_COMMIT
RUN git clone --filter=blob:none --no-checkout --depth=1 https://github.com/sigstore/protobuf-specs.git /protobuf-specs && \
    cd /protobuf-specs && \
    git sparse-checkout set --no-cone '/**/*.proto' && \
    git checkout ${PROTOBUF_SPECS_COMMIT} && \
    rm -rf .git

FROM golang:1.24.2-alpine@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS go-builder

ADD go.* tools/

# the specific versions of these tools are in hack/go.mod so that Dependabot can bump them for updates
RUN cd tools && GOBIN=/go/tools go install tool

FROM gcr.io/distroless/static-debian12:nonroot@sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dc

COPY --from=go-builder /go/tools/protoc-* /usr/local/bin/
COPY --from=protoc-builder /protobuf/bin/protoc /usr/local/bin/
COPY --from=protoc-builder /protobuf/include/google /opt/include/google
COPY --from=protoc-builder /googleapis /googleapis
COPY --from=protoc-builder /protobuf-specs/protos /protobuf-specs

ENTRYPOINT ["/usr/local/bin/protoc", "--plugin=protoc-gen-go=/usr/local/bin/protoc-gen-go", "--plugin=protoc-gen-go-grpc=/usr/local/bin/protoc-gen-go-grpc", "--plugin=protoc-gen-grpc-gateway=/usr/local/bin/protoc-gen-grpc-gateway", "--plugin=protoc-gen-openapiv2=/usr/local/bin/protoc-gen-openapiv2"]

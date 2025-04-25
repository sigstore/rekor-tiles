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

# TODO(#66): replace this whole build with https://github.com/sigstore/protobuf-specs/issues/542

PROTOC_REKOR_IMAGE = protoc-rekor

PLATFORM ?= linux/amd64
UID ?= $(shell id -u)
GID ?= $(shell id -g)
DOCKER_BUILD = docker build --platform ${PLATFORM} --build-arg UID=${UID}
DOCKER_RUN = docker run --platform ${PLATFORM} --user ${UID}:${GID}

PROTOC_VERSION_TAG = v29.3
PROTOC_VERSION = 29.3
PROTOC_CHECKSUM = sha256:3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a
GOOGLEAPIS_COMMIT = dd1210af5bee414c9e606f5637e0eb0fd9d894e8
PROTOBUF_SPECS_COMMIT = 68cc7d273f0a2ade2f8c9c56c0da094f481eabd5 #v0.4.0

GO_MODULE = github.com/sigstore/rekor-tiles
PROJECT_DIR = $(shell cd ..; pwd)
PROTOS = $(shell cd ..; find api/proto/ -iname "*.proto" | sed 's|^|/project_dir/|')
PROTO_OUT = pkg/generated/protobuf
OPENAPI_OUT = docs/openapi
MOUNT_POINT = /project_dir

all: protos

# generate Go protobuf code
protos: proto-image
	@echo "Generating go protobuf files"
	@mkdir -p ${PROJECT_DIR}/${OPENAPI_OUT}
	${DOCKER_RUN} -v ${PROJECT_DIR}:${MOUNT_POINT} ${PROTOC_REKOR_IMAGE} \
		-I/opt/include -I/googleapis -I/protobuf-specs -I${MOUNT_POINT}/api/proto \
		--go_out=${MOUNT_POINT} \
		--go_opt=module=${GO_MODULE} \
		--go-grpc_opt=module=${GO_MODULE} --go-grpc_out=${MOUNT_POINT} \
		--grpc-gateway_opt=module=${GO_MODULE} --grpc-gateway_opt=logtostderr=true --grpc-gateway_out=${MOUNT_POINT} \
		--openapiv2_out=${MOUNT_POINT}/${OPENAPI_OUT} \
    ${PROTOS}
	${DOCKER_RUN} -v ${PROJECT_DIR}:${MOUNT_POINT} ${PROTOC_REKOR_IMAGE} \
		-I/opt/include -I/googleapis -I/protobuf-specs -I${MOUNT_POINT}/api/proto \
		--python_out=${MOUNT_POINT} \
    ${PROTOS}


.PHONY: proto-image
proto-image: Dockerfile
	@echo "Generating go proto Docker image"
	${DOCKER_BUILD} -t ${PROTOC_REKOR_IMAGE} -f Dockerfile \
    --build-arg BUILDKIT_SYNTAX=docker/dockerfile:1 \
	  --build-arg PROTOC_VERSION=${PROTOC_VERSION} \
	  --build-arg PROTOC_VERSION_TAG=${PROTOC_VERSION_TAG} \
	  --build-arg PROTOC_CHECKSUM=${PROTOC_CHECKSUM} \
	  --build-arg GOOGLEAPIS_COMMIT=${GOOGLEAPIS_COMMIT} \
    --build-arg PROTOBUF_SPECS_COMMIT=${PROTOBUF_SPECS_COMMIT} \
	  .

# to recover from a situation where a stale layer exist, just  purging the
# docker image via `make clean` is not enough. Re-building without layer
# cache is the only solution.
.PHONY: proto-no-cache
proto-no-cache:
	@echo "Building development docker images with disabled cache"
	@DOCKER_CACHE="--no-cache" make proto

# clean up generated files (not working? try sudo make clean)
clean:
	docker rmi -f ${PROTOC_REKOR_IMAGE}
	rm -rf ${PROJECT_DIR}/docs/openapi/*
	rm -rf ${PROJECT_DIR}/pkg/generated/protobuf/*

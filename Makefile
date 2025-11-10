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

.PHONY: all test clean lint gosec ko-local tools ldflags

all: protos rekor-server-gcp rekor-server-aws

GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

PROTO_DIRS = pkg/generated/protobuf/ api/proto/
SRC = $(shell find . -iname "*.go" | grep -v -e $(subst $() $(), -e ,$(strip $(PROTO_DIRS))))
PROTO_SRC = $(shell find $(PROTO_DIRS))

SIGSTORE_PROTO_BUILDER = $(shell grep FROM Dockerfile.protobuf-specs | cut -d' ' -f 2)
ZIZMOR = $(shell grep FROM Dockerfile.zizmor | cut -d' ' -f 2)

# for docker protobuf build
GO_MODULE = github.com/sigstore/rekor-tiles/v2
PROTOS = $(shell find api/proto/ -iname "*.proto" | sed 's|^|/project_dir/|')
PROTO_OUT = pkg/generated/protobuf
OPENAPI_OUT = docs/openapi
MOUNT_POINT = /project_dir
PLATFORM ?= linux/amd64
UID ?= $(shell id -u)
GID ?= $(shell id -g)
DOCKER_RUN = docker run --platform ${PLATFORM} --user ${UID}:${GID}

REKOR_LDFLAGS=-buildid= \
              -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
              -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
              -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
              -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)
SERVER_LDFLAGS=$(REKOR_LDFLAGS)

GOBIN = $(abspath ./tools/bin)

lint:
	go tool addlicense -l apache -c "The Sigstore Authors" -ignore "third_party/**" -v *
	go tool goimports -w $(SRC)
	docker run -t --rm -v $(PWD):/app -w /app \
		--user $(shell id -u):$(shell id -g) \
		-v $(shell go env GOCACHE):/.cache/go-build -e GOCACHE=/.cache/go-build \
		-v $(shell go env GOMODCACHE):/.cache/mod -e GOMODCACHE=/.cache/mod \
		-v ~/.cache/golangci-lint:/.cache/golangci-lint -e GOLANGCI_LINT_CACHE=/.cache/golangci-lint \
		$(shell awk -F '[ @]' '/FROM golangci\/golangci-lint/{print $$2; exit}' Dockerfile.golangci-lint) golangci-lint run -v ./...
	docker run -t --rm -v $(PWD):/source $(ZIZMOR) /source

gosec: ## Run gosec security scanner
	$(GOBIN)/gosec ./...

rekor-server-gcp: $(SRC) $(PROTO_SRC)
	CGO_ENABLED=0 go build -trimpath -tags gcp -ldflags "$(SERVER_LDFLAGS)" -o rekor-server-gcp ./cmd/rekor-server-gcp

rekor-server-aws: $(SRC) $(PROTO_SRC)
	CGO_ENABLED=0 go build -trimpath -tags aws -ldflags "$(SERVER_LDFLAGS)" -o rekor-server-aws ./cmd/rekor-server-aws

# Legacy target for backwards compatibility - builds GCP version
rekor-server: rekor-server-gcp
	cp rekor-server-gcp rekor-server

ldflags: ## Print ldflags
	@echo $(SERVER_LDFLAGS)

test: ## Run all tests
	@echo "Running tests with AWS backend..."
	go test -tags aws ./...
	@echo "Running tests with GCP backend..."
	go test -tags gcp ./...

ko-local: ## Build container images locally using ko
	KO_DOCKER_REPO=ko.local LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --image-refs rekorImagerefs \
		github.com/sigstore/rekor-tiles/v2/cmd/rekor-server-gcp \
		github.com/sigstore/rekor-tiles/v2/cmd/rekor-server-aws

# generate Go protobuf code
protos:
	@echo "Generating go protobuf files"
	@mkdir -p ${OPENAPI_OUT}
	${DOCKER_RUN} -v ${PWD}:${MOUNT_POINT} ${SIGSTORE_PROTO_BUILDER} \
		-I/opt/include -I/googleapis -I/grpc-gateway -I/protobuf-specs -I${MOUNT_POINT}/api/proto \
		--go_out=${MOUNT_POINT} \
		--go_opt=module=${GO_MODULE} \
		--go-grpc_opt=module=${GO_MODULE} --go-grpc_out=${MOUNT_POINT} \
		--grpc-gateway_opt=module=${GO_MODULE} --grpc-gateway_opt=logtostderr=true --grpc-gateway_out=${MOUNT_POINT} \
		--openapiv2_out=${MOUNT_POINT}/${OPENAPI_OUT} \
    ${PROTOS}

clean: ## Remove built binaries and artifacts
	rm -rf docs/openapi/*
	rm -rf pkg/generated/protobuf/*
	rm -rf dist
	rm -rf hack/tools/bin
	rm -rf rekor-server rekor-server-gcp rekor-server-aws

##################
# help
##################

help: ## Display this help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

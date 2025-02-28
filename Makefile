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

.PHONY: all test clean lint gosec ko-local

all: rekor-server

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

REKOR_LDFLAGS=-X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
              -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
              -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
              -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)
SERVER_LDFLAGS=$(REKOR_LDFLAGS)

GOBIN ?= $(shell go env GOPATH)/bin

lint: ## Run golangci-lint checks
	$(GOBIN)/golangci-lint run -v ./...

addlicense: ## Add licenses to source files
	$(GOBIN)/addlicense -l apache -c "The Sigstore Authors" -ignore "third_party/**" -v *

gosec: ## Run gosec security scanner
	$(GOBIN)/gosec ./...

rekor-server:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(SERVER_LDFLAGS)" -o rekor-server ./cmd/rekor-server

test: ## Run all tests
	go test ./...

ko-local: ## Build container images locally using ko
	KO_DOCKER_REPO=ko.local LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --image-refs rekorImagerefs \
		github.com/sigstore/rekor-tiles/cmd/rekor-server

protos:
	$(MAKE) -C protoc-builder protos

clean: ## Remove built binaries and artifacts
	rm -rf dist
	rm -rf hack/tools/bin
	rm -rf rekor-server
	$(MAKE) -C protoc-builder clean

##################
# help
##################

help: ## Display this help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

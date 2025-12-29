# /usr/bin/env bash
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

set -e

export STORAGE_EMULATOR_HOST=localhost:7080

docker compose -f compose.yml up -d --build --wait --wait-timeout 60
cleanup() {
	echo "cleaning up"
	docker compose down
}
trap cleanup EXIT

echo "running pre-freeze tests"
go test -v -tags=e2e,freeze -run TestGCPPreFreeze ./tests

echo "setting rekor to read-only"
composefile=compose.yml.tmp
sed -e '/"serve"/a\' -e '    - "--read-only"' compose.yml > $composefile
cleanup_tmp() {
	cleanup
	rm $composefile
}
trap cleanup_tmp EXIT

docker compose -f compose.yml down rekor && docker compose -f $composefile up -d rekor --wait --wait-timeout 60

echo "freezing checkpoint"
go run cmd/freeze-checkpoint/gcp/main.go --gcp-bucket "tiles" --signer-filepath tests/testdata/pki/ed25519-priv-key.pem --hostname rekor-local

echo "running post-freeze tests"
go test -v -tags=e2e,freeze -run TestGCPPostFreeze ./tests

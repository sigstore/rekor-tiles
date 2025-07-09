#!/usr/bin/env bash
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

source ./util.sh

TEST_validate_shard1_entry_for_second_validity_window() {
  local id
  id=1.1
  local artifact_path
  artifact_path=$WORKDIR/data.$id.txt
  go run client/verify/verify.go -bundle "$WORKDIR/bundle.$id.json" -key "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" "$artifact_path"
}

TEST_validate_shard2_active_for_second_validity_window() {
  local id
  id=2.1
  local artifact_path
  artifact_path=$WORKDIR/data.$id.txt
  make_artifact "$artifact_path"
  go run client/sign/sign.go -bundle-out "$WORKDIR/bundle.$id.json" -key-out "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" -signing-config "$WORKDIR/targets/signing_config.json" "$artifact_path"
  assert_log_index "$WORKDIR/bundle.$id.json" 1
  assert_shard "$WORKDIR/bundle.$id.json" shard2.rekor.local
  go run client/verify/verify.go -bundle "$WORKDIR/bundle.$id.json" -key "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" "$artifact_path"
}

step2() {
  # Test that the second service is selected by signing config.
  # Test that verifying bundles from the old service still works.
  message "TEST: shard 1 verification works during second validity window"
  TEST_validate_shard1_entry_for_second_validity_window
  message "TEST: shard2 works during second validity window"
  TEST_validate_shard2_active_for_second_validity_window
}

# Go runtime doesn't trust the fake time, have it look up time from this variable.
NOW=$(date --iso-8601=sec)
export NOW

step2

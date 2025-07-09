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

set -e

source ./util.sh

# Validate that the first shard is online and produces valid bundles.
# The first shard is discovered through signing_config.json which only contains one shard at this point.
SETUP_validate_shard1_initialized() {
  local id
  id=1.0
  local artifact_path
  artifact_path=$WORKDIR/data.$id.txt
  make_artifact "$artifact_path"
  go run client/sign/sign.go -bundle-out "$WORKDIR/bundle.$id.json" -key-out "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" -signing-config "$WORKDIR/targets/signing_config.json" "$artifact_path"
  assert_log_index "$WORKDIR/bundle.$id.json" 0
  go run client/verify/verify.go -bundle "$WORKDIR/bundle.$id.json" -key "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" "$artifact_path"
}

# Validate that the second shard is online and produces valid bundles.
# The second shard is not discoverable through signing_config.json because its validity period has not started, so use its URL directly
SETUP_validate_shard2_initialized() {
  local id
  id=2.0
  local artifact_path
  artifact_path=$WORKDIR/data.$id.txt
  make_artifact "$artifact_path"
  go run client/sign/sign.go --rekor-url "$SHARD2_URL" -bundle-out "$WORKDIR/bundle.$id.json" -key-out "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" -signing-config "$WORKDIR/targets/signing_config.json" "$artifact_path"
  assert_log_index "$WORKDIR/bundle.$id.json" 0
  assert_shard "$WORKDIR/bundle.$id.json" shard2.rekor.local
  go run client/verify/verify.go -bundle "$WORKDIR/bundle.$id.json" -key "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" "$artifact_path"
}

TEST_validate_shard1_active_for_first_validity_window() {
  local id
  id=1.1
  local artifact_path
  artifact_path=$WORKDIR/data.$id.txt
  make_artifact "$artifact_path"
  go run client/sign/sign.go -bundle-out "$WORKDIR/bundle.$id.json" -key-out "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" -signing-config "$WORKDIR/targets/signing_config.json" "$artifact_path"
  assert_log_index "$WORKDIR/bundle.$id.json" 1
  assert_shard "$WORKDIR/bundle.$id.json" shard1.rekor.local
  go run client/verify/verify.go -bundle "$WORKDIR/bundle.$id.json" -key "$WORKDIR/entry-key.$id.pem" -trusted-root "$WORKDIR/targets/trusted_root.json" "$artifact_path"
}

run() {
  # Set up TSA.
  message "SETUP: Starting TSA"
  start_tsa
  local tsakey
  tsakey=$(get_tsa_cert)

  # Bring up the first shard. Set up trusted_root.json and signing_config.json
  # to point to it. Signing and verifying should work normally.
  message "SETUP: starting first shard"
  local shard1_key
  shard1_key=$(new_key 1)
  start_shard1 "$tsakey" "$shard1_key"

  # Test that the one service works.
  SETUP_validate_shard1_initialized

  # Bring up the second shard. Add the second shard to trusted_root.json and
  # signing_config.json to be chosen for signing in the future but be valid for
  # verification now. Signing should upload entries to the first shard, but
  # verification should work for both.
  message "SETUP: starting second shard"
  local shard2_key
  shard2_key=$(new_key 2)
  start_shard2 "$tsakey" "$shard1_key" "$shard2_key"
  SETUP_validate_shard2_initialized

  # Test that the second service works, using its URL explicitly, and check that
  # verifying works with the new TUF keys.
  # Test that the original service is still selected by signing config and still works.
  message "TEST: shard 1 works during first validity window"
  TEST_validate_shard1_active_for_first_validity_window

  # Turn off the old shard to demonstrate that there is no longer any reliance on the old shard.
  # In reality, the old shard would remain running and accepting write requests until the end of its validity window.
  docker_down shard1
  # Run the tests for the second validity window.
  # faketime can only run commands, not functions or expressions,
  # so they are contained in a second script.
  # The second shard becomes valid in signing_config.json 1 minute in the future, so
  # jump ahead to land in that window.
  faketime '65 seconds' ./step2-test.sh

  # Shut down all the containers.
  message "CLEANUP: turning down services"
  cleanup
}

run

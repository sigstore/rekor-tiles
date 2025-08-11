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

export WORKDIR=${WORKDIR:-$(mktemp -d)}

export SHARD1_URL=http://localhost:3003
export SHARD2_URL=http://localhost:3030

new_trusted_root() {
  local flags
  while [[ "$#" -gt 0 ]]; do
    case $1 in
      -rekor)
        local key=$2
        local origin=$3
        local start=$4
        local end
        if [ "$#" -gt 4 ] && [ "${5:0:1}" != "-" ]; then
          end=$5
          shift
        fi
        shift 4
        flags="$flags --rekor-key $key,$origin --rekor-url http://${origin} --rekor-start-time $start"
        if [ -n "$end" ]; then
          flags="$flags --rekor-end-time $end"
        fi
        ;;
    esac
  done

  local targetdir
  targetdir=${WORKDIR}/targets
  mkdir -p "$targetdir"
  cosign trusted-root create $flags \
    --out "${targetdir}/trusted_root.json"
}

new_signing_config() {
  local shard1_tlog
  shard1_tlog=$1
  local shard1_start
  shard1_start=$2
  local shard1_end
  local shard2_tlog
  local shard2_start
  if [ "$#" -gt 2 ] ; then
    shard1_end=$3
    shard2_tlog=$4
    shard2_start=$5
  fi

  local shard1_tlog_cfg
  shard1_tlog_cfg=$(tlog_configs "$shard1_tlog" "$shard1_start" "$shard2_start")
  local shard2_tlog_cfg
  if [ -n "$shard2_tlog" ] ; then
    shard2_tlog_cfg=$(tlog_configs "$shard2_tlog" "$shard2_start")
  fi
  local signing_config
  signing_config=$(cat <<EOF
{
  "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
  "rekorTlogUrls": [],
  "rekorTlogConfig": {
    "selector": "ANY"
  }
}
EOF
)
  signing_config=$(echo "$signing_config" | jq ".rekorTlogUrls[0] = $shard1_tlog_cfg")
  if [ -n "$shard2_tlog_cfg" ] ; then
    signing_config=$(echo "$signing_config" | jq ".rekorTlogUrls[1] = $shard2_tlog_cfg")
  fi
  echo "$signing_config" > "${WORKDIR}/targets/signing_config.json"
}

tlog_configs() {
  local url
  url=$1
  local start
  start=$2
  local end
  end=$3

  local inner
  inner=$(jq -n --arg "start" "$start" '$ARGS.named')
  if [ -n "$end" ] ; then
    inner=$(echo "$inner" | jq '. += { "end": "'"$end"'"}')
  fi
  jq -n --arg "url" "$url" --arg "majorApiVersion" 2 \
    --argjson "validFor" "$inner" \
    --arg "operator" "sharding-test" '$ARGS.named'
}

new_key() {
  local id
  id=$1
  local private
  private=ed25519-priv-${id}.pem
  local public
  public=ed25519-pub-${id}.pem
  local keydir
  keydir=${WORKDIR}/pki
  mkdir -p "$keydir"
  openssl genpkey -algorithm ed25519 -out "${keydir}/${private}"
  openssl pkey -in "${keydir}/${private}" -pubout -out "${keydir}/${public}"
  echo "${keydir}/${public}"
}

start_shard1() {
  local rekorkey_shard1
  rekorkey_shard1=$1

  # generate trusted root
  local shard1_start
  shard1_start=$(date --iso-8601=sec)
  new_trusted_root -rekor "$rekorkey_shard1" shard1.rekor.local "$shard1_start"
  # generate signing config
  new_signing_config http://localhost:3003 "$shard1_start"

  # start the service
  docker compose --profile shard1 up -d --wait
}

start_shard2() {
  local rekorkey_shard1
  rekorkey_shard1=$1
  local rekorkey_shard2
  rekorkey_shard2=$2

  local shard1_start
  shard1_start=$(date -d '1 minute ago' --iso-8601=sec)
  local shard2_start
  shard2_start=$(date -d '1 minute' --iso-8601=sec)
  local shard1_end
  shard1_end=$(date -d '1 week' --iso-8601=sec)
  new_trusted_root -rekor "$rekorkey_shard1" shard1.rekor.local "$shard1_start" "$shard1_end" -rekor "$rekorkey_shard2" shard2.rekor.local "$(date --iso-8601=sec)"
  new_signing_config http://localhost:3003 "$shard1_start" "$shard2_start" http://localhost:3030 "$shard2_start"

  docker compose --profile shard2 up -d --wait
}

assert_log_index() {
  local bundle_path
  bundle_path=$1
  local expect_log_index
  expect_log_index=$2
  local got_log_index
  got_log_index=$(jq -r .verificationMaterial.tlogEntries[0].logIndex "$bundle_path")
  if [[ $expect_log_index -ne $got_log_index ]] ; then
    echo "Unexpected log index for entry: expected $expect_log_index, got $got_log_index"
    exit 1
  fi
}

assert_shard() {
  local bundle_path
  bundle_path=$1
  local expect_shard_origin
  expect_shard_origin=$2
  local got_checkpoint_envelope
  got_checkpoint_envelope=$(jq -r .verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope "$bundle_path")
  if ! echo "$got_checkpoint_envelope" | grep "$expect_shard_origin" >/dev/null ; then
    echo "Unexpected origin for server, entry was sent to incorrect server: expected $expect_shard_origin, got $got_checkpoint_envelope"
    exit 1
  fi
}

make_artifact() {
  local artifact_path
  artifact_path=$1
  echo "$RAND" > "$artifact_path"
}

message() {
  local content
  content=$1
  local length
  (( length=${#content}+4 ))
  printf "#%.0s" $(seq $length)
  printf "\n"
  printf "# %s #" "$content"
  printf "\n"
  printf "#%.0s" $(seq $length)
  printf "\n"
}

docker_down() {
  local shard=$1
  docker compose --profile $shard down
}

cleanup() {
  docker_down shard1 # should already be off
  docker_down shard2
}

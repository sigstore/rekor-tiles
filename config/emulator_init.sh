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

PS4='+\D{%Y-%m-%d %H:%M:%S} $LINENO: '

set -eux

gcloud config configurations list | grep emulator | grep True || gcloud config configurations create emulator
gcloud config set auth/disable_credentials true
gcloud config set project $GCP_PROJECT
gcloud config set api_endpoint_overrides/spanner $SPANNER_EMULATOR_REST_HOST

gcloud spanner instances list | grep $SPANNER_INSTANCE || \
    gcloud spanner instances create $SPANNER_INSTANCE \
        --no-user-output-enabled \
        --nodes=1 \
        --description="test spanner instance for rekor tiles" \
        --config=emulator-config
gcloud spanner databases list --instance $SPANNER_INSTANCE | grep $SPANNER_DB || \
    gcloud spanner databases create $SPANNER_DB \
        --no-user-output-enabled \
        --instance $SPANNER_INSTANCE
spanner_antispam_db=$SPANNER_DB-antispam
gcloud spanner databases list --instance $SPANNER_INSTANCE | grep $spanner_antispam_db || \
    gcloud spanner databases create $spanner_antispam_db \
        --no-user-output-enabled \
        --instance $SPANNER_INSTANCE

echo "done" > /root/finished

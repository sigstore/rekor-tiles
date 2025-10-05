# Sharding Playbook

This playbook walks through the steps to create a new log shard
for Rekor v2.

Roughly, the steps are:

1. Create the GCP resources with Terraform
2. Generate key material
3. Spin up the new infrastructure with Helm and Terraform
4. Verify the health of the infrastructure with manual testing
5. Run prober tests
6. Update TrustedRoot with the new key material and SigningConfig with the new shard URL
7. Turn down the old shard

## Terraform Module Changes

New shards are declared as additional modules under the respective
environment. This is a different pattern than other modules, which are all
initialized through the
[`sigstore` module](https://github.com/sigstore/terraform-modules/tree/main/gcp/modules/sigstore).
This design allowed deployers to initialize this one module and set all required variables, at
which point you'd have a complete Sigstore stack on GCP. The downside of this approach is
private deployers that don't need all GCP infrastructure have to initialize all resources,
though deployers can always initialize each module referenced in `sigstore` individually.

The other downside to referencing the `sigstore` module is that an update to a sub-module
will concurrently update all deployed shards.  Declaring each shard as its own module allows us
to make updates to shards one-by-one.

The tiled transparency log module we'll reference in Terraform is
[`tiles_tlog`](https://github.com/sigstore/terraform-modules/tree/main/gcp/modules/tiles_tlog).

## Steps

### Temporarily Remove Org Restriction

We are restricted from creating public buckets, which are required for
the storage backend for Rekor v2 and Tessera. Temporarily disable
the `iam.allowedPolicyMemberDomains` constraint.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2938)

For production, update the `projects_project-rekor` module. For staging,
update the `projects_projectsigstore-staging` module. These modules come from
[this file](https://github.com/sigstore/public-good-instance/blob/main/iam/resource_hierarchy/main.tf).

Run `terraform plan` and `terraform apply` using
[Provision sigstore.dev organization](https://github.com/sigstore/public-good-instance/actions/workflows/iam-resource-hierarchy.yml).

### Create GCP resources

To add a new shard, create a module under either
[`staging.tf`](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/staging/1-infrastructure/staging.tf)
or
[`production.tf`](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/production/1-infrastructure/production.tf).

Follow the [example PR](https://github.com/sigstore/public-good-instance/pull/3144), which
will create the required resources.

Note: Do not include the monitoring module `gcp/modules/monitoring/rekorv2` from the example. This will be added
in a later step. The service must be deployed before creating metrics.

Note: You should omit `key_name`, which will be set to a default value of
`checkpoint-signer-key-encryption-key`.

Note: You should omit `bucket_id_length`, which will append a random ID to the bucket
name to make it unguessable, so that read traffic must go through the load balancer.

Modules should be named based on the year and how many shards
have been created in the year. For example, the module should
be named `tiles_tlog_log2026_1` for the first shard in 2026. We'll
use `log2026-1` as the name of the shard itself for this document.

Update `general.auto.tfvars` to include the shard variable values:

```
rekor_tiles_shards = {
  "log2026-1" = {
    cluster_namespace_suffix                = "rekor-tiles-system"
    bucket_name_suffix                      = "sigstore-dev-rekor-tiles"
    spanner_processing_units                = 100
    spanner_instance_name_suffix            = "rekor-tiles"
    spanner_instance_display_name_suffix    = "rekor-tiles"
    network_endpoint_group_http_name_suffix = "rekor-tiles-neg"
    network_endpoint_group_grpc_name_suffix = "rekor-tiles-neg-grpc"
    // network_endpoint_group_zones = ["us-central1-c", "us-central1-f", "us-central1-b"] 
  }
}
```

Note that `network_endpoint_group_zones` needs to remain commented out.
Terraform will error out trying to discover the network endpoint group (NEG) resources
if we declare the zones but the NEGs haven't been created by GKE through the Helm chart yet.

Update `production.tf` or `staging.tf` based on the example. Make sure to update
the `module` names, `shard_name` variables, and the name of the map key for `var.rekor_tiles_shards`.

Ignore the code scanning and defsec alerts for the public bucket and load balancer, as that's expected.

After merging, run `terraform plan` through the GitHub Actions workflow
for [staging](https://github.com/sigstore/public-good-instance/actions/workflows/env-staging.yml)
or [prod](https://github.com/sigstore/public-good-instance/actions/workflows/env-prod.yml).
Confirm the expected resources are created, then run `terraform apply` through the workflow.

### Create Key Material

The public-good instance uses a Tink keyset to sign checkpoints. Tink
encrypts a signing key using a "key encryption key" (KEK) managed by GCP KMS,
and loads the key into memory on service startup.

Tink is beneficial for reliability and cost reduction - KMS is now only
a startup dependency rather than a runtime dependency, and signing happens
exclusively in memory.

To create a shard signing key:

1. Grant yourself access to use the new KEK. Update the `staging.tf`
or `production.tf` config to include the following IAM resource. The shard
keyring name will be `<shard name>-rekor-tiles-keyring`, e.g. `log2026-1-rekor-tiles-keyring`.

```
resource "google_kms_key_ring_iam_member" "rekor-tiles-keyring" {
  key_ring_id = "<project-rekor or projectsigstore-staging>/global/<name of shard keyring>"
  role        = "roles/cloudkms.cryptoOperator"

  member = "user:<username>@sigstore.dev"
}
```

Request a review from an infrastructure maintainer and merge.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2942)

2. Run `terraform plan` and `terraform apply` using the GHA workflow.

3. [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install) if not already installed.

4. Authenticate to gcloud with application credentials: `gcloud auth application-default login`

5. Checkout [`scaffolding`](https://github.com/sigstore/scaffolding), and using
   [`create-tink-keyset`](https://github.com/sigstore/scaffolding/tree/main/cmd/create-tink-keyset), create an encrypted Tink keyset:

```
go run ./cmd/create-tink-keyset \
  --origin <log origin, e.g. schemeless URL> \
  --key-template ED25519 \
  --out enc-keyset.cfg \
  --key-encryption-key-uri gcp-kms://projects/<project name>/locations/<region>/keyRings/<key-ring>/cryptoKeys/checkpoint-signer-key-encryption-key \
  --public-key-out public.b64 \
  --key-id-out keyid.b64
```

Example:

```
go run ./cmd/create-tink-keyset \
  --origin log2026-1.rekor.sigstore.dev \
  --key-template ED25519 \
  --out enc-keyset.cfg \
  --key-encryption-key-uri gcp-kms://projects/projectsigstore-staging/locations/global/keyRings/log2026-1-rekor-tiles-keyring/cryptoKeys/checkpoint-signer-key-encryption-key \
  --public-key-out public.b64 \
  --key-id-out keyid.b64
```

If there's an error that mentions `invalid_grant`, make sure you've run `gcloud auth application-default login`.
IAM bindings sometimes take a few minutes to propagate as well.

Note we won't use [tinkey](https://developers.google.com/tink/tinkey-overview#installation) since
that requires a Java runtime environment and won't output the public key.

Save the output file `enc-keyset.cfg`, which will be used as a value in the Helm chart,
and `public.b64` and `keyid.b64`, which will be distributed in the TUF repo.

6. **Revoke IAM access** by reverting the PR and removing `google_kms_key_ring_iam_member`, and run `terraform plan` and `terraform apply`.

### Create Kubernetes namespace

Each shard is isolated in its own Kubernetes namespace. For either
[production](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/production/helm-charts-values/argocd-apps.yaml)
or
[staging](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/staging/helm-charts-values/argocd-apps.yaml),
add a destination namespace:

```
projects:
  utilities:
    ...
    destinations:
      ...
      - namespace: log2026-1-rekor-tiles-system
        server: https://kubernetes.default.svc
```

[Example PR](https://github.com/sigstore/public-good-instance/pull/2953)

Run `terraform apply` with the "Stage of terraform to run" being `all`, not `infra-only`,
because you're updating ArgoCD's configuration.

### Create Kubernetes Resources

Update the ArgoCD configuration for either
[production](https://github.com/sigstore/public-good-instance/blob/main/argocd/bootstrap-utilities/production/values.yaml)
or
[staging](https://github.com/sigstore/public-good-instance/blob/main/argocd/bootstrap-utilities/staging/values.yaml)
to include the new shard.

Follow the [example PR](https://github.com/sigstore/public-good-instance/pull/3151),
which will set up the deployment, pod monitoring, and gRPC secret. More information is below.

Under `rekorTiles.shards`, copy the previous shard instantiation, and update
the values accordingly based on the Terraform resource names. In particular:

* Update `shardName`
* For `signer.tink.keyset`, copy the contents of `enc-keyset.cfg` (Since this value is encrypted, it's safe to include
it in the config rather than use GCP Secrets). Make sure `signer.tink.key` is set to either the KMS `key_name`
or the default value `checkpoint-signer-key-encryption-key`.
* Update `gcp.bucket` to be the name of the bucket without the `shardName` prefix. Note that this will have a random ID
appended to it, e.g. `sigstore-dev-rekor-tiles-7dd04f40ece69668c26c`. You'll need to retrieve the random ID by looking
at the bucket name on GCP.

Additionally, create the `PodMonitoring` collector for gathering metrics from the pod. Add a new
[`PodMonitoring` collector](https://github.com/sigstore/public-good-instance/blob/main/argocd/utilities/manifest/staging/prometheus-monitoring/rekor-tiles.yaml),
updating `metadata.name` and `metadata.namespace` for the collector.

To be able to route gRPC traffic to the Kubernetes backend, you'll need to provide a TLS
certificate to the service. The certificate can be expired and will be shared between all
shards, as its only purpose is to allow the load balancer to send encrypted traffic
(a requirement imposed by the load balancer for HTTP2/gRPC traffic).
Create an ExternalSecret configuration based on the example. Update the name of the
file and `metadata.namespace`. All other values will remain the same.

Note: If this is the first time you're deploying a shard in an environment, you'll need to do a
[one time initialization of the GCP secret](#one-time-grpc-gcp-secret-initialization).

Merge, and wait for ArgoCD to create the resources and spin up the service. You can monitor the GKE UI,
or view the ArgoCD dashboard. To get access, follow the
[playbook](https://github.com/sigstore/public-good-instance/blob/main/playbooks/argo-access.md).

You may have to manually "sync" if there's any errors. Note that the namespace must exist
before any resources can be created. Also note that the gRPC secret must be created before
the service pods can be started.

Once this completes, all Kubernetes resources will have been created. However, the service will not
yet be available for traffic.

### Update Network Endpoint Groups

In the last step, NEGs were created by Kubernetes. Now we need to update Terraform to
reference these NEGs to be able to route traffic from the frontend load balancer to the
backend Kubernetes resources.

Uncomment `network_endpoint_group_zones` in `general.auto.tfvars` or set `network_endpoint_group_zones` to
`["us-central1-c", "us-central1-f", "us-central1-b"]`.  Note that these zones are based on
where the VM instances are, which are currently the same for staging and production.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2955)

Merge, `terraform plan` and `terraform apply`. The service should now be live! We'll verify everything's working
as expected in a moment.

### Reapply Org Restriction

Finally, reapply the org restriction to prevent public buckets.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2978)

Run `terraform apply` using
[Provision sigstore.dev organization](https://github.com/sigstore/public-good-instance/actions/workflows/iam-resource-hierarchy.yml).

### Create GCP Monitoring resources

Now that the service is deployed, create the metrics, alerts and dashboards for the service.
Follow the example below, updating the `shard_name`.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3282)

Merge, `terraform plan`, and `terraform apply`.

## Verify Shard Health

In GCP, make sure you're viewing the correct project for either production or staging.

### Verify the load balancer

Go to [Load Balancing](https://console.cloud.google.com/net-services/loadbalancing/list/loadBalancers).
You should see an application load balancer for Rekor, e.g. `log2026-1-rekor-lb`. It should have
a green checkmark, with 2 backend services (0 instance groups, 6 network endpoint groups), and 1
backend bucket. Click on it.

Under Frontend, you should see HTTPS with an SSL certificate.

Under Routing Rules, there should be two rules, one for the domain, and a default rule.

Under Backend and Backend services, you should see two backend services. One should be suffixed by
`rekor-k8s-grpc-neg-backend-service` and the other `k8s-neg-backend-service`.
For each backend, e.g. `log2026-rekor-tiles-neg-grpc`, you should see a green checkmark with "1 of 1" under Healthy.
This means that every backend connection from the frontend load balancer to the Compute VM is functional, as verified
by a healthcheck for HTTP and HTTP/2 traffic.

Under Backend buckets, you should see a storage bucket and Cloud CDN should be Enabled.

### Verify the read path

Verify that a checkpoint is served from the Storage bucket, e.g.

```
curl https://log2026-1.rekor.sigstage.dev/api/v2/checkpoint

log2026-1.rekor.sigstage.dev
0
YR3vjr9qTpYPib0tUJT/7/pAPuK9xDOibMncp2aQAJE=

— log2026-1.rekor.sigstage.dev 8w1amdxKovmc7H9+4lnx/vSeAQo9zo8cr8EHFCVviWMtTmm/Xw+zGDnBni9/mHHa1hFXIQlC29+YyaOXRxduvbE20Qg=
```

### Verify the write path

Following
[these instructions](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md#rekor-v2-the-bash-way),
test the write path for the new shard. This will sign an entry with a private key and upload
the signing event to the log.

## WIP: Update Prober

We will need a mechanism for running prober tests against a new deployment before we've
distributed an updated SigningConfig and TrustedRoot. Assuming this is a parameter to
a GitHub Actions workflow, a deployer should provide the URL to the new shard and run
prober tests.

Tracked in https://github.com/sigstore/rekor-tiles/issues/46. The prober will pick up
new shards from the SigningConfig, with the latest active shard having no end date.
Only the active shard will be used to test write traffic. All other shards in the SigningConfig
will still support read traffic.

## Update TUF Verification Material

Now that the shard is up and we've successfully signed and verified using it, we will
update the TrustedRoot and SigningConfig files distributed via TUF so that clients
can verify proofs from the shard and use the shard during signing.

For TrustedRoot, the validity window for the shard should be from the point
when the shard was spun up. For SigningConfig, the validity window should start
after the TUF timestamp expires to guarantee all clients will have picked up
the latest TrustedRoot. In practice for our TUF root with timestamp validity
of one week, this means setting the validity window to be at least one week
past when the TUF targets are signed.

You will need four timestamps:

* New shard's start time for TrustedRoot, which should be when the shard was spun up.
* Previous shard's end for TrustedRoot: Clients will consider this shard's entry timestamps invalid
if they are after this date. This must be after the start of the new shard. It doesn't have to be
overly precise, and can be updated in a future TUF signing event.
* New shard's start time for SigningConfig, which should be one week past when the root signing PR is merged
and new TUF repository is published. Overestimate by at least a week of the expected merge date,
as you don't want clients to start using the new shard before all clients
have picked up the latest TrustedRoot.
* Previous shard's end time for SigningConfig: This should be the start time of the new shard.

### Get shard public key

You should have the log public key saved in `public.b64` from when you generated the key,
and the log's checkpoint key ID in `keyid.b64`.
If you don't have the public key, look at the service logs to find the public key, which
is logged on service startup. If you don't have the key ID, you can use
[this script](https://go.dev/play/p/oiE6LjeqLnj) to generate the ID given the key.

The key and ID are formatted such that you just need to copy them into a new
instance in the TrustedRoot.

### Update TrustedRoot

Update the TrustedRoot for the new shard's key material, with the
latest shard added to the **end** of the list: 

```
{
  "mediaType": "...",
  "tlogs": [
    // previous shard
    {
      "baseUrl": "...",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "...",
        "keyDetails": "...",
        "validFor": {
          "start": "...",
          "end": "<UTC timestamp that is after the shard is turned read-only>"
        }
      },
      "logId": {
        "keyId": "..."
      }
    },
    // new shard
    {
      "baseUrl": "https://<year-revision>.rekor.(sigstore|sigstage).dev",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "<base64-encoded public key>",
        "keyDetails": "ED25519",
        "validFor": {
          "start": "<UTC timestamp for when shard was spun up>"
        }
      },
      "logId": {
        "keyId": "<base64-encoded checkpoint key ID>"
      }
    }
  ],
  ...
}
```


Update the SigningConfig for the new shard, with the latest
shard added to the **beginning** of the list:

```
{
    "media_type": "...",
    "ca_urls": [...],
    "oidc_urls": [...],
    // sorted from newest to oldest
    "rekor_tlog_urls": [
        // new shard
        {
            "url": "<year-revision>.rekor.(sigstore|sigstage).dev",
            "major_api_version": 2,
             "valid_for": {
                "start": "<UTC timestamp, at least one week past when to-be-signed TUF timestamp will expire>"
            }
        },
        // previous shard
        {
            ...,
            "valid_for": {
                "start": "...",
                "end": "<valid_for.start for new shard>"
            }
        }
    ],
    "rekor_tlog_config": {...},
    "tsa_urls": [...],
    "tsa_config": {...},
}
```

Follow the playbooks in https://github.com/sigstore/root-signing and
https://github.com/sigstore/root-signing-staging to orchestrate a new
signing event.

## Update transparency-dev configuration

We need to manually update the witness under the transparency-dev
organization so that the shard will be monitored.

Update [omniwitness](https://github.com/transparency-dev/witness/blob/main/omniwitness/logs.yaml),
whose list is used by [Armored Witness](https://github.com/transparency-dev/armored-witness).

[Example PR](https://github.com/transparency-dev/witness/pull/424/)

## Turn Down Old Shard

Wait a week, until all clients have received updated SigningConfigs
and started signing using the new shard, and are using the updated TrustedRoot
to verify inclusion proofs.

### Verify write traffic

Verify write traffic to the previous shard has gone down to ~0 QPS.
If there is significant traffic, look at the user agent and see if you
can figure out who's calling the service.

[Example link](https://console.cloud.google.com/monitoring/metrics-explorer;duration=P1D?pageState=%7B%22xyChart%22:%7B%22constantLines%22:%5B%5D,%22dataSets%22:%5B%7B%22plotType%22:%22LINE%22,%22pointConnectionMethod%22:%22GAP_DETECTION%22,%22targetAxis%22:%22Y1%22,%22timeSeriesFilter%22:%7B%22aggregations%22:%5B%7B%22alignmentPeriod%22:%2260s%22,%22crossSeriesReducer%22:%22REDUCE_SUM%22,%22groupByFields%22:%5B%22resource.label.%5C%22namespace%5C%22%22%5D,%22perSeriesAligner%22:%22ALIGN_RATE%22%7D%5D,%22apiSource%22:%22DEFAULT_CLOUD%22,%22crossSeriesReducer%22:%22REDUCE_SUM%22,%22filter%22:%22metric.type%3D%5C%22prometheus.googleapis.com%2Frekor_v2_new_hashedrekord_entries%2Fcounter%5C%22%20resource.type%3D%5C%22prometheus_target%5C%22%22,%22groupByFields%22:%5B%22resource.label.%5C%22namespace%5C%22%22%5D,%22minAlignmentPeriod%22:%2260s%22,%22perSeriesAligner%22:%22ALIGN_RATE%22%7D%7D,%7B%22plotType%22:%22LINE%22,%22pointConnectionMethod%22:%22GAP_DETECTION%22,%22targetAxis%22:%22Y1%22,%22timeSeriesFilter%22:%7B%22aggregations%22:%5B%7B%22alignmentPeriod%22:%2260s%22,%22crossSeriesReducer%22:%22REDUCE_SUM%22,%22groupByFields%22:%5B%22resource.label.%5C%22namespace%5C%22%22%5D,%22perSeriesAligner%22:%22ALIGN_RATE%22%7D%5D,%22apiSource%22:%22DEFAULT_CLOUD%22,%22crossSeriesReducer%22:%22REDUCE_SUM%22,%22filter%22:%22metric.type%3D%5C%22prometheus.googleapis.com%2Frekor_v2_new_dsse_entries%2Fcounter%5C%22%20resource.type%3D%5C%22prometheus_target%5C%22%22,%22groupByFields%22:%5B%22resource.label.%5C%22namespace%5C%22%22%5D,%22minAlignmentPeriod%22:%2260s%22,%22perSeriesAligner%22:%22ALIGN_RATE%22%7D%7D%5D,%22options%22:%7B%22mode%22:%22COLOR%22%7D,%22y1Axis%22:%7B%22label%22:%22%22,%22scale%22:%22LINEAR%22%7D%7D%7D&project=projectsigstore-staging)

### Post on Slack

Make a post on Slack letting the community know we'll be freezing
and turning down the log. Include that the turndown should cause
no issues for anyone using Sigstore clients.

### Update monitor for status page

Log into [Betterstack](https://betterstack.com/), which hosts Sigstore's status page
([prod](https://status.sigstore.dev/), [staging](https://status.sigstage.dev/)). You'll
need to work with someone in the oncall rotation to login with the magic link, using
`oncall@sigstore.dev` to email a login link to the oncall group.

Update the Rekor v2 [monitor](https://uptime.betterstack.com/team/t59712/monitors) for
either staging or prod. Click the three dots on the right side and click "Configure".
Change the "URL to monitor" to be for the new shard, and click "Save changes".

### WIP: Disable alerts for old shard

Make sure to either disable or remove via Terraform alerts for the old shard
for failing healthchecks for the write path or missing metrics. As we turn down the service
and delete resources, we expect that healthchecks will start to fail.

Remove the monitoring module from Terraform, either from `staging.tf` or `production.tf`.
Merge and run `terraform plan` and `terraform apply`.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3175)

As we create more alerting, we'll finalize this section with specific alerts to remove.
We may need to add a `freeze_shard` variable that disables write-only metrics.
For now, we'll remove the entire monitoring module.

### Remove Kubernetes backend services from Load Balancer

The Kubernetes backend services must be removed from the load balancer URL map
before deleting the backend services. Terraform isn't smart enough to do this
in a single `apply`, as it tries to delete the backend services while they're
still in use, which throws a resource-in-use error.

In the Terraform configuration `staging.tf` or `production.tf` for the respective `tiles_tlog` module,
set `lb_backend_turndown = true`. Merge the PR, and `terraform plan` and `terraform apply`.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3284)

### Delete Kubernetes backends from backend services

Kubernetes manages the creation and deletion of network endpoint groups (NEGs),
while Terraform manages the creation and deletion of backend services which reference
the NEGs. We must first remove all Kubernetes backends from the backend services
before deleting the NEGs, otherwise ArgoCD will stall on the deletion of the namespace
since there will still be a reference to an existing Kubernetes object.

In the Terraform configuration `staging.tf` or `production.tf` for the respective `tiles_tlog` module,
comment out `network_endpoint_group_zones` or set it to `[]`, effectively reverting
this [example PR](https://github.com/sigstore/public-good-instance/pull/2955).

[Example PR](https://github.com/sigstore/public-good-instance/pull/3285/) commenting out NEG zones

Merge, `terraform plan` and `terraform apply`.

After this is merged, there will still be Kubernetes backend service resources
in GCP, but they won't be referenced in the load balancer and will contain no
NEG backends. The backend service resources will be cleaned up later.

### Delete Kubernetes resources

Turn down the previous shard by removing the previous shard from `rekorTiles.shards`.
We can turn down the Kubernetes pods because the server only serves the write path -
the read path is exclusively served via GCP resources (Load Balancer, Storage).

Remove the `PodMonitoring` collector and the Kubernetes gRPC secret as well for
the shard.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3176)

Merge.

ArgoCD will not automatically delete the resources since we have disabled
automatic pruning. You'll need to access ArgoCD and manually sync and prune.

First, access ArgoCD following
[the instructions](https://github.com/sigstore/public-good-instance/blob/main/playbooks/argo-access.md).

You'll need to sync and prune three applications. The recommended order is:

* `prometheus-monitoring`, to clean up the pod monitor
* `private-key-secret`, to clean up the gRPC TLS secret
* `bootstrap-utilities`, which should kick off the removal of `rekor-tiles-<log shard name>`
  * Note: If deletion stalls, under the `rekor-tiles-<log shard name>` application, you may need to manually sync the namespace to trigger it to be pruned. This may be due to the namespace getting recreated.

To sync and prune, for each application, click "SYNC", select the "PRUNE" checkbox, and
click "SYNCHRONIZE".

### Delete GCP resources

We only need a subset of GCP resources to serve read traffic. To save costs,
we can turn down the databases and destroy the KEK (indirectly destroying the signing key),
along with deleting the Compute backend services for routing to the deleted pods.

#### Remove database protection

First, remove the protection bit on the databases. In the Terraform configuration `staging.tf`
or `production.tf` for the respective `tiles_tlog` module,
set `spanner_database_sequencer_deletion_protection` and `spanner_database_antispam_deletion_protection`
to `false`. Create a PR, merge, `terraform plan`, and `terraform apply`.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3177)

#### Delete resources

To delete the KEK, databases, and Compute resources, set `freeze_shard` to `true`.
Leave all variables as they are - even though their values won't be used, most are
still required.

[Example PR](https://github.com/sigstore/public-good-instance/pull/3180)

Merge, `terraform plan`, and `terraform apply`. The Terraform plan should
show deletion of:

* Compute resources
  * Kubernetes gRPC and HTTP backend services
  * Backend service health checks
  * Firewall rules for the health checks
* KMS resources
  * Key encryption key (KEK)
  * IAM decrypter and KMS member roles for the workload identity
* Spanner
  * Sequencer and antispam databases
  * Instance (backups should be automatically deleted)
  * IAM DB admin role for the workload identity
* GCS
  * IAM role for managing the GCS bucket for the workload identity
* Monitoring
  * IAM roles for timeseries and descriptors creation for the workload identity

### Prober

The prober should have stopped writing to the shard already since the SigningConfig
will specify the new shard. The prober will continue testing read traffic, discovering
the shard path via the TrustedRoot.

# Appendix

## One-time gRPC GCP secret initialization

gRPC traffic between the load balancer and the K8s backend service is encrypted
over TLS. Since we'd prefer to have TLS terminate at the load balancer, we can
create a single TLS certificate and key to be shared across all shards. It can
even expire as per the documentation.

We create a GCP secret once per environment, which is mounted by
[External Secrets Operator](https://external-secrets.io/latest/).
To create the secret, grant yourself `roles/secretmanager.admin`, and run:

```
openssl req -new -newkey rsa:2048 -days 1825 -nodes -x509 -keyout rekor-grpc.key -out rekor-grpc.crt -subj "/C=US/ST=WA/L=Kirkland/O=Sigstore/OU=Rekor/CN=localhost" -addext "subjectAltName = IP:127.0.0.1" -addext "keyUsage = critical,digitalSignature,keyEncipherment"

openssl pkcs12 -passout "pass:" -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -out rekor-grpc.p12 -inkey rekor-grpc.key -in rekor-grpc.crt

gcloud secrets create rekor-grpc-tls --replication-policy="automatic" --data-file="rekor-grpc.p12" --project projectsigstore-staging
```

This will generate a TLS key and self-signed certificate, merge them into a PKCS #12 archive, and upload that archive.

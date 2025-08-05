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

### Create GCP resources

To add a new shard, create a module under either
[`staging.tf`](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/staging/1-infrastructure/staging.tf)
or
[`production.tf`](https://github.com/sigstore/public-good-instance/blob/main/terraform/environments/production/1-infrastructure/production.tf).

[Example PR](https://github.com/sigstore/public-good-instance/pull/2907/). For the example,
you'll only need to look at `staging.tf` and `general.auto.tfvars`. Remember to update
the correct environment for production or staging.

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
the `module` name, `shard_name` variable, and the name of the map key for `var.rekor_tiles_shards`.

After merging, run `terraform plan` through the GitHub Actions workflow
for [staging](https://github.com/sigstore/public-good-instance/actions/workflows/env-staging.yml)
or [prod](https://github.com/sigstore/public-good-instance/actions/workflows/env-prod.yml).
Confirm the expected resources are created, then run `terraform apply` through the workflow.
Note this will also remove the org restriction.

### Create Key Material

The public-good instance uses a Tink keyset to sign checkpoints. Tink
encrypts a signing key using a "key encryption key" (KEK) managed by GCP KMS,
and loads the key into memory on service startup.

Tink is beneficial for reliability and cost reduction - KMS is now only
a startup dependency rather than a runtime dependency, and signing happens
exclusively in memory.

To create a shard KEK:

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
  --key-template ED25519 \
  --out enc-keyset.cfg \
  --key-encryption-key-uri gcp-kms://projects/<project name>/locations/<region>/keyRings/<key-ring>/cryptoKeys/checkpoint-signer-key-encryption-key \
  --public-key-out public.pem
```

Example:

```
go run ./cmd/create-tink-keyset \
  --key-template ED25519 \
  --out enc-keyset.cfg \
  --key-encryption-key-uri gcp-kms://projects/projectsigstore-staging/locations/global/keyRings/log2026-1-rekor-tiles-keyring/cryptoKeys/checkpoint-signer-key-encryption-key \
  --public-key-out public.pem
```

Note we won't use [tinkey](https://developers.google.com/tink/tinkey-overview#installation) since
that requires a Java runtime environment and won't output the public key.

Save the output file `enc-keyset.cfg`, which will be used as a value in the Helm chart,
and `public.pem`, which will be distributed in the TUF repo.

6. Revoke IAM access by reverting the PR and removing `google_kms_key_ring_iam_member`, and run `plan` and `apply`.

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

### Create Kubernetes gRPC Secret

To be able to route gRPC traffic to the Kubernetes backend, you'll need to provide a TLS
certificate to the service. The certificate can be expired and will be shared between all
shards, as its only purpose is to allow the load balancer to send encrypted traffic
(a requirement imposed by the load balancer for HTTP2/gRPC traffic).

Create an ExternalSecret configuration based on the example below. Update the name of the
file and `metadata.namespace`. All other values will remain the same.

[Example](https://github.com/sigstore/public-good-instance/blob/main/argocd/utilities/manifest/staging/privateKeySecret/log2025-alpha1-rekor-grpc-tls.yaml)

Merge, and ArgoCD will automatically create the Kubernetes secret using the TLS certificate and
private key stored in GCP Secret Manager.

### Create Kubernetes Resources

Update the ArgoCD configuration for either
[production](https://github.com/sigstore/public-good-instance/blob/main/argocd/bootstrap-utilities/production/values.yaml)
or
[staging](https://github.com/sigstore/public-good-instance/blob/main/argocd/bootstrap-utilities/staging/values.yaml)
to include the new shard.

Under `rekorTiles.shards`, copy the previous shard instantiation, and update
the values accordingly based on the Terraform resource names. In particular, update the `shardName`.
For `keyset`, copy the contents of `enc-keyset.cfg` (Since this value is encrypted, it's safe to include
it in the config rather than use GCP Secrets). Make sure `signer.tink.key` is set to either the KMS `key_name`
or the default value `checkpoint-signer-key-encryption-key`.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2947)

Merge, and wait for ArgoCD to create the resources and spin up the service. You can monitor the GKE UI,
or view the ArgoCD dashboard. To get access, follow the
[playbook](https://github.com/sigstore/public-good-instance/blob/main/playbooks/argo-access.md).

Once this completes, all Kubernetes resources will have been created. However, the service will not
yet be available for traffic.

### Update Network Endpoint Groups

In the last step, NEGs were created by Kubernetes. Now we need to update Terraform to
reference these NEGs to be able to route traffic from the frontend load balancer to the
backend Kubernetes resources.

Uncomment `network_endpoint_group_zones` in `general.auto.tfvars` or set `network_endpoint_group_zones` to
`["us-central1-c", "us-central1-f", "us-central1-b"]`. 

[Example PR](https://github.com/sigstore/public-good-instance/pull/2955)

Merge, `plan` and `apply`. The service should now be live! We'll verify everything's working
as expected in a moment.

### Reapply Org Restriction

Finally, reapply the org restriction to prevent public buckets.

[Example PR](https://github.com/sigstore/public-good-instance/pull/2978)

### WIP: Add Monitoring and Alerting

Add a `PodMonitoring` collector for gathering metrics from the service
and add Terraform for setting up metrics and alerts on GCP.

Example PRs:

* [`PodMonitoring`](https://github.com/sigstore/public-good-instance/pull/3100/) - Will rollout automatically after merging
* [`Terraform for metrics`](https://github.com/sigstore/public-good-instance/pull/3115/) - `terraform apply` after merging

TODO: Determine if these can be merged earlier in the process

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

You will need three timestamps:

* New shard's start time for TrustedRoot, which should be when the shard was spun up.
* New shard's start time for SigningConfig, which should be one week past when the root-signing PR is merged
and new TUF repository is published. Overestimate (by an hour or even a day) if needed,
as you don't want clients to start using the new shard before all clients
have picked up the latest TrustedRoot.
* Previous shard's end for TrustedRoot: Clients will consider this shard's entry timestamps invalid
if they are after this date. This must be after the start of the new shard. It doesn't have to be
overly precise, and can be updated in a future TUF signing event.

### Get shard public key

You should have the log public key saved in `public.pem` from when you generated the key.
If you don't have the public key, look at the service logs to find the public key, which
is logged on service startup.

The key is PEM-encoded. Remove the PEM header and footer and remove all newline characters to get the base64-encoded PKIX public key.

### Update TrustedRoot

Update the TrustedRoot for the new shard's key material:

```
{
  "mediaType": "...",
  "tlogs": [
    // new shard
    {
      "baseUrl": "https://<year-revision>.rekor.(sigstore|sigstage).dev",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "base64-encoded DER public key",
        "keyDetails": "ED25519",
        "validFor": {
          "start": "<UTC timestamp for when shard was spun up>"
        }
      },
      "logId": {
        "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
      }
    },
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
    ...
  ],
  ...
}
```


Update the SigningConfig for the new shard:

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
                "start": "<UTC timestamp, at least one week past when to-be-signed TUF timestamp will expire>",
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

## Turn Down Old Shard

Wait a week, until all clients have received updated SigningConfigs
and started signing using the new shard, and are using the updated TrustedRoot
to verify inclusion proofs.

### Verify write traffic

Verify write traffic to the previous shard has gone down to ~0 QPS.
If there is significant traffic, look at the user agent and see if you
can figure out who's calling the service.

<!--- TODO: Update with link to monitoring -->

### Post on Slack

Make a post on Slack letting the community know we'll be freezing
and turning down the log.

### WIP: Disable alerts for old shard

Make sure to either disable or remove via Terraform alerts for the old shard
for failing healthchecks for the write path or missing metrics. As we turn down the service
and delete resources, we expect that healthchecks will start to fail.

As we create alerting, we'll finalize this section with what alerts need to be removed.

### Delete Kubernetes resources

Turn down the previous shard by removing the previous shard from `rekorTiles.shards`.
We can turn down the Kubernetes pods because the server only serves the write path -
the read path is exclusively served via GCP resources (Load Balancer, Storage).

Merge and wait for ArgoCD to shut down the server.

### Delete GCP resources

We only need a subset of GCP resources to serve read traffic. To save costs,
we can turn down the databases and destroy the KEK (indirectly destroying the signing key).

First, remove the protection bit on the databases. In the Terraform configuration,
set `spanner_database_sequencer_deletion_protection` and `spanner_database_antispam_deletion_protection`
to `false`. Create a PR, merge, `plan`, and `apply`.

To delete the KEK and databases, set `freeze_shard` to `true`, and remove
`spanner_processing_units`, `spanner_instance_name_suffix`, `spanner_instance_display_name_suffix`,
`keyring_name_suffix`, `key_name`, `kms_crypto_key_algorithm`, `network_endpoint_group_http_name_suffix`,
`network_endpoint_group_grpc_name_suffix`, and `network_endpoint_group_zones`. All other variables
should remain, for the networking stack to serve read traffic from GCS.

### Prober

The prober should have stopped writing to the shard already since the SigningConfig
will specify the new shard. The prober will continue testing read traffic, discovering
the shard path via the TrustedRoot.

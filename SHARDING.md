# Sharding Playbook

This playbook walks through the steps to create a new log shard.
The steps should be the same for Rekor and the CT log, though the
CT process for generating key material may differ.

Roughly, the steps are:

1. Create the GCP resources with Terraform
2. Generate key material
3. Spin up the new infrastructure
6. Update prober
4. Perform manual testing
5. Update TrustedRoot with the new key material and SigningConfig with the new shard URL
6. Turning down the old shard

## Create GCP resources

New shards are declared as additional modules under the respective
environment. This is a different pattern than other modules, which are all
initialized through the `sigstore` module. Declaring each shard as its
own module allows us to make updates to shards one-by-one. Otherwise,
by updating the module reference of `sigstore`, all shards would be
concurrently updated.

To add a new shard, create a module under either
`terraform/environments/staging/1-infrastructure/staging.tf` or
`terraform/environments/production/1-infrastructure/production.tf`.
Name the module `rekor-tiles-log-<year>-<revision>`, e.g.
`rekor-tiles-log-2025-1`.

<!--- TODO: Add code pointers for module example -->

Update `general.auto.tfvars` to include the shard variable values:

```
rekor_tiles_shards = {
  "log2025-1" = {
    ...
  },
  "log2025-2" = {
    ...
  },
  "log2026-1" = {
    ...
  }
}
```

After merging, run `terraform plan` through the GitHub Actions workflow
for [staging](https://github.com/sigstore/public-good-instance/actions/workflows/env-staging.yml)
or [prod](https://github.com/sigstore/public-good-instance/actions/workflows/env-prod.yml).
Confirm the expected resources are created, then run `terraform apply` through the workflow.

## Creating Key Material

The public-good instance uses a Tink keyset to sign checkpoints. Tink
encrypts a signing key using a "key encryption key" managed by GCP KMS,
and loads the key into memory on service startup.

Tink is beneficial for reliability and cost reduction - KMS is now only
a startup dependency rather than a runtime dependency, and signing happens
exclusively in memory.

To create a shard signing key:

1. Grant yourself access to use the new signing key. Update the `staging.tf`
or `production.tf` config to include:

```
resource "google_kms_key_ring_iam_member" "rekor-tiles-keyring" {
  key_ring_id = "<project-rekor or projectsigstore-staging>/<location, e.g. global>/<name of shard keyring>"
  role        = "roles/cloudkms.cryptoOperator"

  member = "user:<username>@sigstore.dev"
}
```

2. Run `terraform plan` and `terraform apply` using the GHA workflow.

3. Using [tinkey](https://developers.google.com/tink/tinkey-overview#installation), create an encrypted Tink keyset:

```
tinkey create-keyset --key-template ED25519 --out enc-keyset.cfg --master-key-uri gcp-kms://projects/<project name>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>
```

Save the output file `enc-keyset.cfg`, which will be used as a value in the Helm chart.

4. Revoke IAM access by removing `google_kms_key_ring_iam_member`, and run `plan` and `apply`.

## Creating K8s Resources

Update `argocd/bootstrap-utilities/staging/values.yaml` or `argocd/bootstrap-utilities/production/values.yaml`
to include the new shard. Under `rekor-tiles.shards`, copy the previous shard instantiation, and update
the values accordingly based on the Terraform resources names. For `keyset`, copy the contents of
`enc-keyset.cfg` (Since this value is encrypted, it's secure to include it in the config rather than
use GCP Secrets).

<!--- TODO: Add code pointers for values -->

Merge, and wait for ArgoCD to create the resources and spin up the service.

## Update Prober

Update the prober configuration for
[staging](https://github.com/sigstore/sigstore-probers/blob/8608ff2cbc6a9121f12c75cb01a18f32e1428195/.github/workflows/prober-staging.yml#L28)
or
[prod](https://github.com/sigstore/sigstore-probers/blob/8608ff2cbc6a9121f12c75cb01a18f32e1428195/.github/workflows/prober-prod.yml#L26)
to specify the new shard name. Merge and kick off the workflow.

<!--- TODO: Update prober to support testing against multiple Rekor shard URLs -->
<!--- TODO: Update prober to test reads and writes separately, since frozen shards will still support reads -->

## Perform Manual Testing

Using Cosign, test signing and verification against this new shard. You will need to manually update the SigningConfig
and TrustedRoot files and pass them via CLI flags since those files are pulled from TUF and will not yet have been updated.

<!--- TODO: Update with example TrustedRoot and SigningConfig -->

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

You will need to estimate two timestamps:

* New shard's start for SigningConfig, which should be one week past when the TUF
timestamp will be signed. Overestimate if needed, as you don't want clients to start
using the new shard before all clients have picked up the latest TrustedRoot.
* Previous shard's end for TrustedRoot, which is when the previous shard's write path
is turned off. This must be after the start of the new shard. It doesn't have to
overly precise, and can be updated in a future TUF signing event.

Update the TrustedRoot for the new shard's key material:

```
{
  "mediaType": "...",
  "tlogs": [
    // new shard
    {
      "baseUrl": "https://<year-revions>.rekor.(sigstore|sigstage).dev",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "base64-encoded DER public key",
        "keyDetails": "ED25199",
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
          "end": "<UTC timestamp for approx when the shard will be shut down>"
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

Verify write traffic to the previous shard has gone down to ~0 QPS.

<!--- TODO: Update with link to monitoring -->

### Prober

Update the prober configuration to remove the previous shard URL for testing writes.

### K8s

Turn down the previous shard by removing the previous values for `rekor-tiles.shards`.
We can turn down the Kubernetes pods because the server only serves the write path -
the read path is exclusively served via GCP resources (Load Balancer, Storage).

Merge and wait for ArgoCD to shut down the server.

### Remove GCP Resources

We only need a subset of GCP resources to serve read traffic. To save costs,
we can turn down the database and destroy the signing key.

<!--- TODO: Specify how we should do this -->

<!--- TODO: Specify how to convey to monitors the shard is frozen.
May need another TUF target signing if we're baking the checkpoint into TrustedRoot.
-->
# Rekor v2

Rekor v2, aka rekor-tiles or Rekor on Tiles, is a redesigned and modernized [Rekor](https://github.com/sigstore/rekor),
Sigstore's signature transparency log, transitioning its backend to a modern,
[tile-backed transparency log](https://transparency.dev/articles/tile-based-logs/) implementation to
simplify maintenance and lower operational costs.

More information (documents are shared with [sigstore-dev](https://groups.google.com/g/sigstore-dev), join the group to get access):

* [Proposal](https://docs.google.com/document/d/1Mi9OhzrucIyt-UCLk_FxO2_xSQZW9ow9U3Lv0ZB_PpM/edit?resourcekey=0-4rPbZPyCS7QDj26Hk0UyvA&tab=t.0#heading=h.bjitqo6lwsmn)
* [Design doc](https://docs.google.com/document/d/1ZYlt_VFB-lxbZCcTZHN-6KVDox3h7-ePp85pNpOUF1U/edit?resourcekey=0-V3WqDB22nOJfI4lTs59RVQ&tab=t.0#heading=h.xzptrog8pyxf)

## Public-good instance

The Sigstore community hosts a productionized instance of Rekor v2 with a 99.5% availability SLO.
See the [status page](https://status.sigstore.dev/) for uptime metrics.

Use the public-good instance's TUF repository to determine the URL of the active instance.
Note that the community instance's URL will change approximately every 6 months when
we "shard" the log, creating a new log instance to keep the size of the log maintainable.
Sigstore clients will pull the latest log shard URL from the TUF-distributed
[SigningConfig](https://github.com/sigstore/root-signing/blob/main/targets/signing_config.v0.2.json),
and will fetch both active and inactive shard public keys from the
[TrustedRoot](https://github.com/sigstore/root-signing/blob/main/targets/trusted_root.json).

We have not yet distributed the current Rekor v2 URL in the SigningConfig, to give users
adequate time to update their clients to support verifying entries from Rekor v2.
If you want to start using Rekor v2, construct a signing config, adding the following
instance as the first entry in the `rekorTlogUrls` list:

```
    {
      "url": "https://log2025-1.rekor.sigstore.dev",
      "majorApiVersion": 2,
      "validFor": {
        "start": "2025-10-06T00:00:00Z"
      },
      "operator": "sigstore.dev"
    },
```

## Installation

We provide prebuilt binaries and containers for private deployments.

* Download the latest binary from [Releases](https://github.com/sigstore/rekor-tiles/releases)
* Pull the latest container from [GHCR](https://github.com/sigstore/rekor-tiles/pkgs/container/rekor-tiles)
* Install Rekor v2 via [Helm](https://github.com/sigstore/helm-charts/tree/main/charts/rekor-tiles)

## Security Reports

If you find any issues, follow Sigstore's [security policy](https://github.com/sigstore/rekor-tiles/security/policy)
to report them.

## Local Development

### Deployment

Run `docker compose up --build --wait` to start the service along with emulated Google Cloud Storage and Spanner instances.

Run `docker compose down` to turn down the service, or `docker compose down --volumes` to turn down the service and delete
persisted tiles.

### Making a request

Follow the [client documentation](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md#rekor-v2-the-bash-way)
for constructing a request and parsing a response.

### Testing

Run unit tests with `go test ./...`.

Follow the [end-to-end test documentation](https://github.com/sigstore/rekor-tiles/blob/main/tests/README.md)
for how to run integration tests against a local instance.

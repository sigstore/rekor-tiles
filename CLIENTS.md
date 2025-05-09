# Client Changes for Rekor v2

This document outlines the changes clients need to make to support
Rekor v2.

## Rekor v2 API

Rekor v2 supports HTTP or gRPC, like Fulcio. For Go, we have implemented a client
already. For other languages, they can either use the
[OpenAPI docs](https://github.com/sigstore/rekor-tiles/tree/main/docs/openapi),
[gRPC service proto](https://github.com/sigstore/rekor-tiles/tree/main/api/proto),
or create their own client. 

The service implements one write API, `/api/v2/log/entries`. Example JSON request bodies
below:

```jsonc
// Request with a Fulcio certificate
{
    "hashedRekordRequestV0_0_2": {
        // Must use hash algorithm from key_details
        "digest": "<base64 digest of artifact>",
        "signature": {
            "content": "<base64 signature>",
            "verifier": {
                "x509Certificate": "<base64 DER-encoded certificate>",
                // Must match signing algorithm
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            }
        }
    }
}

// Request with a self-managed key
{
    "hashedRekordRequestV0_0_2": {
        "digest": "<base64 digest of artifact>",
        "signature": {
            "content": "<base64 signature>",
            "verifier": {
                "publicKey": {
                    "rawBytes": "<base64 DER-encoded public key>"
                },
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            }
        }
    }
}

// Request with an attestation
{
    "dsseRequestV0_0_2": {
        "envelope": {
            "payload": "<base64-encoded message>",
            "payloadType": "<type, e.g. application/vnd.in-toto+json>",
            "signatures": [
                {
                    "sig": "<base64-encoded signature>",
                    "keyid": ""
                }
            ]
        },
        "verifier": {
            "x509Certificate": "<base64 DER-encoded certificate>",
            // Must match signing algorithm
            "keyDetails": "PKIX_ECDSA_P256_SHA_256"
        }
    }
}

// Request with an attestation with a self-managed key
{
    "dsseRequestV0_0_2": {
        "envelope": {
            "payload": "<base64-encoded message>",
            "payloadType": "<type, e.g. application/vnd.in-toto+json>",
            "signatures": [
                {
                    "sig": "<base64-encoded signature>",
                    "keyid": ""
                }
            ]
        },
        "verifier": {
            "publicKey": {
                "rawBytes": "<base64 DER-encoded public key>"
            },
            // Must match signing algorithm
            "keyDetails": "PKIX_ECDSA_P256_SHA_256"
        }
    }
}
```

The response will be a
[`TransparencyLogEntry` message](https://github.com/sigstore/protobuf-specs/blob/5296f13d62e7fad428581d969f664c30cc52f549/protos/sigstore_rekor.proto#L94),
which should be persisted in a bundle. Clients no longer need to transform the
Rekor response into a `TLE` message to store in the bundle.

### Two Entry Types

Rekor v2 only supports `hashedrekord` (`HashedRekordRequestV0_0_2`) and
`dsse` (`DSSERequestV0_0_2`) entry types, dropping a number of unused types
such as `jar`, `alpine`, `rpm`, and the older types `rekord` and `intoto`.
Additional types may be added in the future if there is demand, but this
will require updating the client specification so that all clients implement
support for these types.

### Certificate and Public Key Verifiers

Rekor v2 only supports signature verification using a certificate or a
public key, dropping support for PGP, minisign, pkcs7, SSH and TUF.
Additional verifiers may be added in the future, but this will also require
updating the client specification.

### Handling Longer Requests

Clients need to increase request timeouts to at least 10 seconds.

Rekor now batches uploads so that checkpoints are published less frequently.
Additionally, we plan to support synchronous witnessing, where third-party
witnesses independently verify the consistency of the log and Rekor provides
co-signed checkpoints with each upload response.

If a client needs to create multiple entries, it is recommended to upload those
entries in parallel.

## TrustedRoot lookup by checkpoint key ID rather than log ID

Log ID, the SHA-256 digest of the log's public key, is used as a "unique"
identifier for a log. The TransparencyLogEntry message includes it in a
bundle, and clients use that log ID to lookup the correct log public key
in the TrustedRoot to verify the bundle.

Rekor will no longer include log IDs in the response, and instead clients
should use the checkpoint key ID as specified in the
[C2SP spec](https://github.com/C2SP/C2SP/blob/main/signed-note.md#signatures)
to lookup the correct log public key to verify a bundle. Each transparency
log instance in the TrustedRoot will include a `checkpoint_key_id` instead
of a `log_id`.

For more information, log IDs are not necessarily unique identifiers for
a log, since a log may reuse its public key among instances. Additionally,
the log origin is not necessarily a unique identifier, because multiple logs
may be hosted by one origin. Even the combination of both is not necessarily
unique, as a log may create signatures for different purposes with the same
key.

A checkpoint key ID is a truly unique log identifier, which incorporates
the log origin, public key, and the signature type as per the C2SP signed-note
spec linked above.

## Signed RFC 3161 Timestamps

Rekor will no longer return SignedEntryTimestamps or include integrated time
in the response. Clients must fetch an RFC 3161 signed timestamp from a trusted
timestamp authority and include the signed timestamp in the bundle.

Sigstore now operates a timestamp authority at `timestamp.sigstore.dev` and
`timestamp.sigstage.dev` for staging, and the roots for these services will
be included in the TrustedRoot distributed via TUF. Clients may request timestamps
from other trusted timestamp authorities as well. As with other services,
users should specify the verification material for the additional timestamp
authorities in the TrustedRoot.

## SigningConfig support

Clients must implement support for the SigningConfig message, which specifies
the list of URLs that clients should use during signing. Since Rekor shards
will now have unique URLs, we will use the SigningConfig to distribute
the URLs for new shards.

We have published a v2 SigningConfig message to support handling log
sharding, with validity windows (which will prevent a client from writing to a
log before the TrustedRoot is fully distributed) and services with different API
versions (for the transition between Rekor v1 and v2).

A more detailed description of how clients must, should and may handle
the SigningConfig message is in the
[protobuf-specs repo](https://github.com/sigstore/protobuf-specs/blob/dda47952957722e943829af6fe531c005a9fbed6/protos/sigstore_trustroot.proto#L147).

An example SigningConfig with annotations is below:

```jsonc
{
    // Clients do not need to support v0.1
    "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",

    // Fulcio service URLs.
    // Clients must select the first service from the list whose validity window
    // is active and the API version is supported by the client. Clients must
    // select the highest supported API version.
    // Clients can assume that this list is sorted from most recent to oldest.
    "caUrls": [
        {
            "url": "https://fulcio.sigstore.dev",
            "majorApiVersion": 1,
            "validFor": {
                // When clients should start using this service
                "start": "<UTC timestamp>",
                // Optional, when a service is turned down and clients should
                // treat the service as offline
                "end": "<UTC timestamp>"
            },
        }
    ],

    // OIDC service URLs
    "oidcUrls": [
        {
            "url": "https://oauth2.sigstore.dev/auth",
            "majorApiVersion": 1,
            "validFor": {
                "start": "<UTC timestamp>"
            },
        }
    ],

    // Rekor service URLs. This example shows multiple active logs.
    // The client should select the log with the highest API version
    // it supports.
    "rekorTlogUrls": [
        {
            "url": "https://log2025-01.rekor.sigstore.dev",
            "majorApiVersion": 2,
            "validFor": {
                "start": "<UTC timestamp>"
            },
        },
        {
            "url": "https://rekor.sigstore.dev",
            "majorApiVersion": 1,
            "validFor": {
                "start": "<UTC timestamp>"
            },
        }
    ],

    // Rekor service selection
    // "Valid" is defined above to mean the service's validity window is
    // active and the API version is supported by the client.
    "rekorTlogConfig": {
        // EXACT specifies that a client must upload entries to exactly
        // "count" number of valid logs. Clients must throw an error
        // if less than "count" logs are valid. Clients should select
        // logs from the highest available API version, even if "count"
        // logs are not available.
        // May also be ANY, meaning the client should select exactly
        // one valid log. The client can decide how to select it, e.g. random
        // or round-robin if the client tracks state.
        // May also be ALL, which should be all valid logs.
        "selector": "EXACT",
        // Optional, only when EXACT is specified
        "count": 2
    },

    // Timestamp authority URLs
    // Like Rekor, clients should use the TSA config which dictates
    // how many TSAs should be used to request timestamps from.
    "tsaUrls": [
        {
            "url": "https://oauth2.sigstore.dev/auth",
            "majorApiVersion": 1,
            "validFor": {
                "start": "<UTC timestamp>"
            },
        }
    ],

    // Timestamp authority service selection
    "tsaConfig": {
        "selector": "ANY"
    }
}
```

## Removing Online Verification and Search

Rekor no longer provides an API for online verification and search. This includes
the APIs for requesting inclusion proofs by index, by leaf hash and by entry,
and searching for an entry by artifact hash or identity. In the near future,
we will spin up a separate service to support search.

Clients must be given the inclusion proof and checkpoint for an entry,
which must be stored in a bundle.

This should have no impact on clients as inclusion proofs were already
required in bundles. This will only impact monitors, and the read API
changes are detailed below.

## No Attestation Storage

Rekor v1's `intoto` type persisted attestations. Rekor v1's `dsse` type
removed attestation storage as Rekor was not designed to be used as storage
for verification metadata.

In Rekor v2, the `DSSERequestV0_0_2` type will also not support attestation
storage. Attestations should be persisted alongside an artifact, e.g. in
OCI or a package registry, or in a dedicated attestation storage service.

## C2SP Checkpoints

The checkpoints the log provides will conform to the
[C2SP checkpoint spec](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md).
Clients must check that their checkpoint verification implementation properly
handles these checkpoints, which could include:

* Multiple signatures
* Optional extension lines
* Updated key names, which will match the shard URL
* Key IDs calculated per the [signed note spec](https://github.com/C2SP/C2SP/blob/main/signed-note.md#signatures)
  * ECDSA and Ed25519 key IDs are based on the spec
  * For RSA, the signature type is `0xFF` and we append `PKIX-RSA-PKCS#1v1.5`,
    `key ID = SHA-256(key name || 0x0A || 0xFF || PKIX-RSA-PKCS#1v1.5 || public key)[:4]`

## TrustedRoot With Multiple Logs

Clients must verify that verification works with a TrustedRoot
with multiple logs with overlapping validity windows. Confirm that
the client will fetch the correct verification key from the TrustedRoot
by using the log ID (which is the hash of the log's public key).

## Monitoring/Auditing

One of the more significant changes in a tile-backed log is the changes
to the read API. Inclusion and consistency proofs are not served via an
API, rather the client requests the set of tiles necessary to compute
the inclusion or consistency proof.

When monitoring the log searching for entries, the monitor will not request
entries by index, but by tile. Monitors can choose to only fetch complete
tiles or request [partial tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#partial-tiles),
which are the rightmost tiles in a tree that may contain somewhere between 1 and 255 hashes.
It is recommended to request partial tiles, or else the monitor might lag behind
if tiles are not filled frequently.

The APIs to request checkpoints, tiles, and entry bundles are defined
in the
[tlog-tiles spec](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#apis).
For Go, [trillian-tessera](https://github.com/transparency-dev/trillian-tessera/tree/main/client)
provides a client to compute proofs and fetch tiles.

## Future: Witnessing

Witnessing provides independent verification that the log
remains consistent (append-only). Witnessing can either be
asynchronous, where a client requests witnesses verify consistency
proofs, or synchronous, where the log requests witnesses
verify proofs for every checkpoint issued. This results in a
longer request times and a dependency on third-party witnesses,
but results in a strong offline proof of log inclusion. We
will publish a doc later on with more details.

In the initial launch of Rekor v2, checkpoints will not be
witnessed, while we wait for the launch of a public witness
network. Clients do not need to implement verification of
witness signatures initially, but clients should increase
request timeouts to account for the additional time to
sign checkpoints, which we estimate to be <10s.

To verify cosignatures, see the
[spec](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md).

The log will determine which set of witnesses is trusted and the
M-of-N witnesses to fetch signatures from, and this policy will
be distributed by Sigstore's TUF root.

Co-signed checkpoints will also be timestamped, so they can serve
as an independent signed timestamp instead of an RFC 3161 timestamp.

# Rekor v2, the bash way

Clone the service if you haven't already: `git clone https://github.com/sigstore/rekor-tiles.git`

Spin up the service: `docker compose up --build --wait`

Create a signed artifact:

```bash
openssl ecparam -genkey -name prime256v1 > ec_private.pem && openssl ec -in ec_private.pem -pubout > ec_public.pem
head -c 128 < /dev/urandom > artifact
openssl dgst -sha256 -sign ec_private.pem artifact > artifact.sig
openssl dgst -sha256 -verify ec_public.pem -signature artifact.sig artifact # Should return Verified OK
```

Generate artifact digest:

```bash
cat artifact | openssl dgst -binary -sha256 > artifact_dgst
```

Post an entry:

```bash
curl  -H \
 "Accept: application/json" -X \
POST http://localhost:3003/api/v2/log/entries -o rekor_response -d "{ \"hashedRekordRequestV0_0_2\":{ \"digest\":\"$(cat artifact_dgst|base64)\", \"signature\":{ \"content\": \"$(cat artifact.sig | base64)\", \"verifier\": { \"key_details\": \"PKIX_ECDSA_P256_SHA_256\", \"public_key\": { \"raw_bytes\": \"$(openssl base64 -d -in ec_public.pem | base64)\" } } } } }"
```

View the response with `cat rekor_response | jq .` Example:

```json
{
  "logIndex": "0",
  "logId": {
    "keyId": "2AtEIMfG6Y41yK0tcwRTBS2tjhOrjKGIpDkHFgp65g0="
  },
  "kindVersion": {
    "kind": "hashedrekord",
    "version": "0.0.2"
  },
  "integratedTime": "0",
  "inclusionPromise": null,
  "inclusionProof": {
    "logIndex": "0",
    "rootHash": "OWI5MjU1MWIxZTA0NGIzNmQ0ZGE0MTU0M2UwNjEwZjVhNzQyMDNiN2JiOWEzOWYwNDExOTZlMTI2MTg5NmM3NQ==",
    "treeSize": "1",
    "hashes": [],
    "checkpoint": {
      "envelope": "rekor-local\n1\nm5JVGx4ESzbU2kFUPgYQ9adCA7e7mjnwQRluEmGJbHU=\n\n— rekor-local 2AtEIIwnbtxrneJ7L1lQebfBRl7TxK84DTmx+kcZi7A25cBDgESI23f9ylThAlOireJ7U+H8eZF/4kJQcn9o5Qt8mQU=\n"
    }
  },
  "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJoYXNoZWRSZWtvcmRWMF8wXzIiOnsiZGF0YSI6eyJhbGdvcml0aG0iOiJTSEEyXzI1NiIsImRpZ2VzdCI6ImR5ajRlZG5ZSGpONC96c2pqQmVlTGFoUzlzbHA5N1o2N0xUQVZ4anJqWHc9In0sInNpZ25hdHVyZSI6eyJjb250ZW50IjoiTUVRQ0lCK1lQYTlvM1NOMHNRNHVkdUdmK21aeHdGZk9oRlowQ2d5K3A3VnQxbzJTQWlBUEZESHFPQUpMWW12dENXT3NEeU5ZMUg0VjN6bTRORURZczNOeXZIaDFQZz09IiwidmVyaWZpZXIiOnsia2V5RGV0YWlscyI6IlBLSVhfRUNEU0FfUDI1Nl9TSEFfMjU2IiwicHVibGljS2V5Ijp7InJhd0J5dGVzIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFMnNsT2Y4ZVpjajJtb1cydDRVRmo3dkNMNlFwRHprRHFxU1VtbTRPSkNWdklhdUtMeG0wYUdzM1ZNUFBmYXVNUGFNdXRuMC9zM2pnMHJyb0Z4b2ljeWc9PSJ9fX19fX0="
}
```

# Rekor Load Test

This directory contains a [k6](https://k6.io) script for load testing a Rekor v2 server. The test focuses on the write path, submitting `hashedrekord` entries to the transparency log.

## Prerequisites

1.  **Install k6**: Follow the official k6 installation guide.

2.  **Running Rekor v2 Instance**: The load test requires a running instance of `rekor-tiles`. You can start a local instance using Docker Compose from the root of this repository:

    **GCP Backend (default):**
    ```sh
    docker compose up --wait --build
    ```

    **AWS Backend:**
    ```sh
    docker compose -f docker-compose-aws.yml up --wait --build
    ```

    The services will be available at their default ports, which the k6 script is pre-configured to use.

## Running the Test

To execute the load test, navigate to this directory (`tests/loadtest`) and run the following command:

**GCP Backend (default):**
```sh
k6 run k6_rekor_load_test.js
```

**AWS Backend:**
```sh
REKOR_URL=http://localhost:3004/api/v2 GCS_URL=http://localhost:9000/tiles k6 run k6_rekor_load_test.js
```

### Configuration

The test can be configured using environment variables if you need to target a non-default deployment:

*   `REKOR_URL`: The URL for the Rekor write API. Defaults to `http://localhost:3003/api/v2` (GCP) or use `http://localhost:3004/api/v2` for AWS.
*   `GCS_URL`: The URL for the Rekor read API, which is used for the initial health check against the `/checkpoint` endpoint. Defaults to `http://localhost:7080/tiles` (GCP) or use `http://localhost:9000/tiles` for AWS (MinIO).

## Test Scenario

The script simulates a ramp-up of virtual users (VUs) to stress the Rekor server's write endpoint (`/log/entries`).

The test scenario is defined as a `ramping-vus` executor with the following stages:
1.  Ramp up to 5 VUs over 30 seconds.
2.  Ramp up to 20 VUs over 1 minute.
3.  Ramp up to 100 VUs over 30 seconds.
4.  Stay at 100 VUs for 2 minutes.
5.  Ramp down to 0 VUs over 30 seconds.

Each virtual user continuously generates and submits a new `hashedrekord` entry signed with a unique ECDSA P-256 key (generated once per VU).

### Configuration

The number of virtual users and the duration can be configured as well:

```
k6 run --vus 1000 --duration 60s k6_rekor_load_test.js
```

## Metrics and Thresholds

The test will fail if either of these conditions are met:
*   The 95th percentile of request duration (`http_req_duration`) exceeds 10 seconds.
*   The failure rate (`errors`) is greater than 10%.

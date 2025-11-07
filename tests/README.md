# End to End tests

## Running the End to End tests

The e2e tests support multiple storage backends (GCP and AWS). You can control which backends to test using the `TEST_BACKENDS` environment variable.

### Backend Selection

The `TEST_BACKENDS` environment variable accepts the following values:
- `gcp` (default): Test only the GCP backend
- `aws`: Test only the AWS backend
- `gcp,aws`: Test both backends
- `all`: Test all backends

### Testing GCP Backend (Default)

Start the GCP Docker containers:

```sh
docker compose -f compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
# Explicit GCP selection
TEST_BACKENDS=gcp go test -v -tags=e2e ./tests/

# Or without specifying (defaults to GCP)
go test -v -tags=e2e ./tests/
```

Clean up:

```sh
docker compose -f compose.yml down
```

### Testing AWS Backend

Start the AWS Docker containers (MinIO + MySQL):

```sh
docker compose -f docker-compose-aws.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
TEST_BACKENDS=aws go test -v -tags=e2e ./tests/
```

Clean up:

```sh
docker compose -f docker-compose-aws.yml down
```

### Testing Both Backends

To test both GCP and AWS backends in sequence:

```sh
# Start GCP services
docker compose -f compose.yml up -d --build --wait --wait-timeout 60

# Run GCP tests
TEST_BACKENDS=gcp go test -v -tags=e2e ./tests/

# Stop GCP services
docker compose -f compose.yml down

# Start AWS services
docker compose -f docker-compose-aws.yml up -d --build --wait --wait-timeout 60

# Run AWS tests
TEST_BACKENDS=aws go test -v -tags=e2e ./tests/

# Stop AWS services
docker compose -f docker-compose-aws.yml down
```

### Running Specific Tests

To run only specific test functions:

```sh
# GCP backend only
TEST_BACKENDS=gcp go test -v -tags=e2e ./tests/ -run TestReadWrite

# AWS backend only
TEST_BACKENDS=aws go test -v -tags=e2e ./tests/ -run TestPersistentDeduplication

# Both backends
TEST_BACKENDS=all go test -v -tags=e2e ./tests/ -run TestReadWrite
```

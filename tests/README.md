# End to End tests

## Running the End to End tests

### GCP binary

Start the Docker containers from the top level directory:

```sh
docker compose -f compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestGCPSpanner ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose -f compose.yml down --volumes
```

### POSIX binary

Start the Docker containers from the top level directory:

```sh
docker compose -f posix-compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestPOSIX ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose -f posix-compose.yml down --volumes
```

## AWS binary

Start the Docker containers from the top level directory:

```sh
docker compose -f aws-compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestAWS ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose -f aws-compose.yml down --volumes
```

## GCP CloudSQL binary

Start the Docker containers from the top level directory:

```sh
docker compose -f cloudsql-compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestGCPCloudSQL ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose -f cloudsql-compose.yml down --volumes
```

### Identity POSIX Server

Start the Docker containers from the top level directory:

```sh
docker compose -f identity-posix-compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestIdentityPOSIX ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose -f identity-posix-compose.yml down --volumes
```

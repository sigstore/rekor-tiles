# End to End tests

## Running the End to End tests

### GCP binary

Start the Docker containers from the top level directory:

```sh
docker compose -f compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e -run TestGCP ./tests/
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

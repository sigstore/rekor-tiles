# End to End tests

## Running the End to End tests

Start the Docker containers from the top level directory:

```sh
docker compose -f compose.yml up -d --build --wait --wait-timeout 60
```

Run the tests:

```sh
go test -v -tags=e2e ./tests/
```

When finished, you can clean up the Docker containers if desired:

```sh
docker compose down
```

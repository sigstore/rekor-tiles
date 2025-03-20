# Rekor Server

Our GRPC service runs on port `3000`, while the HTTP proxy to the GRPC service runs on port `3000`.

## Healthchecks

We use the GRPC Healthcheck service implementation. Clients wanting to use this initialize their client with a "service config".

 - https://github.com/grpc/grpc-go/tree/eb744dec5da784e7e2fc140ddaa6d2aa645b5371/examples/features/health#client


# The aggregator of the integration stack, from the source tree build-images.sh checked out at the pinned commit (no RocksDB: the stack uses the memory SMT).
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /out/aggregator ./cmd/aggregator

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/aggregator /app/aggregator
EXPOSE 3000

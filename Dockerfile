FROM golang:1.27.1-bookworm AS build
RUN apt-get update && apt-get install --yes --no-install-recommends libsodium-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /out/backup ./cmd/backup

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install --yes --no-install-recommends libsodium23 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/backup /usr/local/bin/backup
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/backup", "server"]

FROM build AS integration-client
RUN cp /out/backup /usr/local/bin/backup && \
    mkdir -p /fixture && \
    printf 'whole-root fixture\n' > /fixture/root-only && \
    chmod 0600 /fixture/root-only && \
    touch -d '@1700000000' /fixture/root-only && \
    ln -s root-only /fixture/root-link

FROM runtime

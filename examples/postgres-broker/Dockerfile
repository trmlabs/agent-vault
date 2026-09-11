# Build the reviewed source, not a downloaded or committed application binary.
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
WORKDIR /src
COPY go.mod go.sum ./
# Corporate TLS interception can use the host's explicitly configured CA bundle.
# The secret mount is build-only; TLS verification is never disabled.
RUN --mount=type=secret,id=demo_ca \
    if [ -s /run/secrets/demo_ca ]; then cat /run/secrets/demo_ca >> /etc/ssl/certs/ca-certificates.crt; fi \
    && go mod download
COPY main.go ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -o /agent-vault .

FROM hashicorp/vault:1.19.4@sha256:b5f675b0bf681568cd7354c697fe4ce953024312d6d23ee7216deda60c192bad AS vault
FROM postgres:16-bookworm@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825
COPY --from=vault /bin/vault /usr/local/bin/vault
COPY --from=build /agent-vault /usr/local/bin/agent-vault
COPY examples/postgres-broker/smoke.sh /usr/local/bin/broker-smoke
USER postgres
WORKDIR /var/lib/postgresql
ENTRYPOINT ["bash", "/usr/local/bin/broker-smoke"]

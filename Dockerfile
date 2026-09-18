# The Privasys service monitor: availability monitoring that can be
# given a real account, built as a reproducible single-binary image.
#
# Nothing is fetched at runtime and nothing is generated at first boot
# except key material on the sealed volume, so the image the platform
# measures is the whole of what runs. The build is single-arch and
# provenance-free on purpose: an OCI attestation index would change the
# manifest digest the enclave pins at OID 1.3.6.1.4.1.65230.3.2.

#
# The RA-TLS client SDK is a sibling module behind a go.mod replace. It is
# cloned at a pinned commit so the image builds from this repository
# alone; bump the ref together with the one in the CI workflow.
ARG RA_TLS_CLIENTS_REF=a5c458d7601eb88ff4eec357037a9421294d8619

FROM golang:1.25-alpine AS builder
ARG RA_TLS_CLIENTS_REF
RUN apk add --no-cache git
RUN git clone https://github.com/Privasys/ra-tls-clients /siblings/ra-tls-clients && \
    git -C /siblings/ra-tls-clients checkout "${RA_TLS_CLIENTS_REF}"

WORKDIR /src

# Dependencies first, so a source-only change does not refetch them. The
# replace path is pointed at the clone, here and again after the full
# copy restores the original go.mod.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN sed -i 's|\.\./\.\./platform/ra-tls-clients/go|/siblings/ra-tls-clients/go|' go.mod && \
    go mod download

COPY . .

ARG VERSION=dev
RUN sed -i 's|\.\./\.\./platform/ra-tls-clients/go|/siblings/ra-tls-clients/go|' go.mod && \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/monitor ./cmd/monitor \
 && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/monitor-verify ./cmd/monitor-verify

# The monitor talks outward to the services it watches, to the callback
# it was given, and to the identity provider's published key set. It
# needs a trust store, and the zone database for agreed service time
# expressed in the customer's own timezone. The zone database is also
# compiled into the binary, so a stripped base image cannot silently
# turn a business-hours schedule into the wrong denominator.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/monitor /usr/local/bin/monitor
# The customer-side verifier ships in the image as well, so an operator
# can hand a counterparty a binary that checks the evidence without
# trusting the monitor that produced it.
COPY --from=builder /out/monitor-verify /usr/local/bin/monitor-verify

# The app manifest. CI also embeds it as the org.privasys.manifest OCI
# label; the file serves GET /privasys.json for runtime introspection.
COPY privasys.json /privasys.json

# Service models baked into the image. A configure call may name one
# with `pack_ref`, or deliver its own inline.
COPY packs /packs

# No fixed port and no EXPOSE: the platform runs containers on the host
# network and injects a unique $PORT per app, which the monitor binds. A
# hard-coded port would collide with a co-located app and fail the
# readiness probe.
ENTRYPOINT ["/usr/local/bin/monitor"]

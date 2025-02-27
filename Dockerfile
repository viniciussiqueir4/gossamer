ARG DEBIAN_VERSION=bullseye-slim
ARG GO_VERSION=1.23.2-bullseye

FROM golang:${GO_VERSION} AS builder

RUN apt-get update && \
    apt-get install -y \
    gcc \
    cmake \
    wget

# Install node source for polkadotjs tests
RUN wget -qO- https://deb.nodesource.com/setup_14.x | bash - && \
    apt-get install -y nodejs

# Install subkey
RUN wget -O /usr/local/bin/subkey https://chainbridge.ams3.digitaloceanspaces.com/subkey-v2.0.0 && \
    chmod +x /usr/local/bin/subkey

WORKDIR /go/src/github.com/ChainSafe/gossamer

# Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy gossamer sources
COPY . .

# Build
ARG GO_BUILD_FLAGS
RUN go build \
    -trimpath \
    -o ./bin/gossamer \
    ${GO_BUILD_FLAGS} \
    ./cmd/gossamer

# Final stage based on Debian
FROM debian:${DEBIAN_VERSION}

WORKDIR /gossamer

EXPOSE 7001 8546 8540

ENTRYPOINT [ "/gossamer/bin/gossamer" ]

COPY chain /gossamer/chain
COPY --from=builder /go/src/github.com/ChainSafe/gossamer/bin/gossamer /gossamer/bin/gossamer

# syntax=docker/dockerfile:1
# tsinject-operator — see README.md.
#
# The build stage runs on the BUILD machine's native architecture and Go
# cross-compiles to the target, so an arm64 workstation builds the amd64
# image with no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY api/ api/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /operator .

# distroless: nothing to debug interactively inside this container — it only
# talks to the Kubernetes and Tailscale APIs.
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.title="tsinject-operator" \
      org.opencontainers.image.description="Operator injecting Tailscale sidecars with asynchronously provisioned OAuth credentials (TailscaleCredential CRD)" \
      org.opencontainers.image.source="https://github.com/davefinster/tsinject"

COPY --from=build /operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]

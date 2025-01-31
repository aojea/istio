
FROM --platform=$BUILDPLATFORM golang:1.23@sha256:7ea4c9dcb2b97ff8ee80a67db3d44f98c8ffa0d191399197007d8459c1453041 AS builder
ARG TARGETARCH BUILDPLATFORM TARGETPLATFORM
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/istio-nri ./cmd/

FROM gcr.io/distroless/static-debian12:debug
COPY --from=builder --chown=root:root /go/bin/istio-nri /bin/istio-nri
CMD ["/bin/istio-nri"]
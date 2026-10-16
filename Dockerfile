# Multi-stage, cross-compiled: the build stage runs on the runner's native arch and Go
# emits the target arch, so linux/arm64 builds need no QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/np-account ./cmd/np-account

FROM alpine:3.22
RUN addgroup -S app && adduser -S -G app app && apk add --no-cache ca-certificates
USER app
COPY --from=build /out/np-account /usr/local/bin/np-account
EXPOSE 8002 8443 8523
ENTRYPOINT ["/usr/local/bin/np-account"]

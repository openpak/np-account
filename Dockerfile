# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod/ \
	--mount=type=bind,source=go.sum,target=go.sum \
	--mount=type=bind,source=go.mod,target=go.mod \
	go mod download -x
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod/ \
	CGO_ENABLED=0 go build -trimpath -o /out/np-account ./cmd/np-account

FROM alpine:3.22
RUN addgroup -S app && adduser -S -G app app && apk add --no-cache ca-certificates
USER app
COPY --from=build /out/np-account /usr/local/bin/np-account
EXPOSE 8002
ENTRYPOINT ["/usr/local/bin/np-account"]

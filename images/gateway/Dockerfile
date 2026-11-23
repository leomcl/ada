FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ada-gateway ./cmd/ada-gateway
COPY internal/gateway ./internal/gateway
COPY internal/sandbox ./internal/sandbox
COPY internal/token ./internal/token
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ada-gateway ./cmd/ada-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ada-gateway /ada-gateway
EXPOSE 8080
ENTRYPOINT ["/ada-gateway"]

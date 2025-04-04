# Stage 1: Build the binary
FROM golang:1.24.2-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for dependency caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code.
COPY . .

# Build the binary from the main package in the root.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o netpoint .

# Stage 2: Create a minimal image with the binary.
FROM alpine:latest

RUN apk update && apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*

COPY --from=builder /app/netpoint /netpoint

EXPOSE 8080

ENTRYPOINT ["/netpoint"]
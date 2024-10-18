# Stage 1: Build the Go application
FROM golang:1.22-alpine3.20 AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && \
    go build -ldflags "-s -w" -o main main.go

# Stage 2: Create a minimal image for running the application
FROM alpine:3.20
RUN apk update && apk upgrade --no-cache && \
    apk --no-cache add ca-certificates libcrypto3 libssl3 openssl
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /app/main .
USER app

ENTRYPOINT ["./main"]

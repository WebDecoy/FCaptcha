# Build stage
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY server-go/go.mod server-go/go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY server-go/*.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fcaptcha-server .

# Runtime stage
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/fcaptcha-server .

# Copy client JS for serving at /fcaptcha.js
COPY client/fcaptcha.js ./static/fcaptcha.js

# Copy demo page for serving at /demo/
COPY demo/index.html ./static/demo/index.html

# Patch demo page for Docker context (same-origin paths)
RUN sed -i 's|src="../client/fcaptcha.js"|src="/fcaptcha.js"|' ./static/demo/index.html && \
    sed -i "s|FCaptcha.serverUrl = 'http://localhost:3000';|FCaptcha.serverUrl = '';|" ./static/demo/index.html

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

# Run
ENV PORT=3000
USER 65532:65532
CMD ["./fcaptcha-server"]

# Build stage
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

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
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

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

# Build stage
FROM golang:1.27.1-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

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
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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

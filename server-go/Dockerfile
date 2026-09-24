FROM golang:1.27.1-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

WORKDIR /app

COPY server-go/go.mod server-go/go.sum ./
RUN go mod download

COPY server-go/*.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fcaptcha-server .

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/fcaptcha-server .
# Widget bundle served at /fcaptcha.js — must live next to the binary so
# resolveClientPath in main.go finds it without an env override.
COPY client/fcaptcha.js ./client/fcaptcha.js

EXPOSE 3000

ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

USER 65532:65532
CMD ["./fcaptcha-server"]

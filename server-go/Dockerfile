FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

WORKDIR /app

COPY server-go/go.mod server-go/go.sum ./
RUN go mod download

COPY server-go/*.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fcaptcha-server .

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

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

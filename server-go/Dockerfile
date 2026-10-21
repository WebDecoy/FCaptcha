FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder

WORKDIR /app

COPY server-go/go.mod server-go/go.sum ./
RUN go mod download

COPY server-go/*.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fcaptcha-server .

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

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

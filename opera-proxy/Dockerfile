FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git ca-certificates
RUN go install github.com/Snawoot/opera-proxy@latest

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/opera-proxy /usr/local/bin/opera-proxy
ENTRYPOINT ["opera-proxy"]

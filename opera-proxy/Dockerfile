FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git ca-certificates
RUN git config --global credential.helper "" && \
    git clone https://github.com/Snawoot/opera-proxy.git /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /usr/local/bin/opera-proxy .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/local/bin/opera-proxy /usr/local/bin/opera-proxy
ENTRYPOINT ["opera-proxy"]

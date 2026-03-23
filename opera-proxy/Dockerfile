FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY opera-proxy /usr/local/bin/opera-proxy
RUN chmod +x /usr/local/bin/opera-proxy
ENTRYPOINT ["opera-proxy"]

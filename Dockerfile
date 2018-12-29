FROM alpine:3.6
MAINTAINER xunchangguo <xunchangguo@gmail.com>
RUN apk add --no-cache ca-certificates
COPY hydra-consent /hydra-consent

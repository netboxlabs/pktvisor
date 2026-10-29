FROM golang:1.26-alpine

LABEL maintainer="netboxlabs"
LABEL version="1.0.0"

# the GOPROXY "|direct" fallback fetches modules with git, which the alpine image lacks
RUN apk add --no-cache git

COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]


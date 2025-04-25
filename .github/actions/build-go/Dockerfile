FROM golang:bullseye

LABEL maintainer="netboxlabs"
LABEL version="1.0.0"

COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]


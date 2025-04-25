FROM ubuntu:noble

ENV BUILD_DEPS "g++ cmake make git pkgconf jq python3 python3-pip python3-setuptools ca-certificates zip curl wget gcc-aarch64-linux-gnu g++-aarch64-linux-gnu"

COPY ./entrypoint.sh /entrypoint.sh

RUN mkdir -p /pktvisor-src

WORKDIR /pktvisor-src

RUN apt-get update && \
    apt-get upgrade --yes && \
    apt-get install --yes --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan --force-reinstall --break-system-packages
    
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]


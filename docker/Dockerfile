FROM ubuntu:noble AS cppbuild

ENV BUILD_DEPS "g++ cmake make automake autoconf git pkgconf jq python3 libasan8 python3-pip python3-setuptools ca-certificates"

RUN \
    apt-get update && \
    apt-get upgrade --yes && \
    apt-get install --yes --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan --break-system-packages

# need git for current hash for VERSION
COPY ./.git/ /pktvisor-src/.git/
COPY ./src/ /pktvisor-src/src/
COPY ./cmd/ /pktvisor-src/cmd/
COPY ./3rd/ /pktvisor-src/3rd/
COPY ./libs/ /pktvisor-src/libs/
COPY ./docker/ /pktvisor-src/docker/
COPY ./golang/ /pktvisor-src/golang/
COPY ./integration_tests/ /pktvisor-src/integration_tests/
COPY ./cmake/ /pktvisor-src/cmake/
COPY ./CMakeLists.txt /pktvisor-src/
COPY ./conanfile.py /pktvisor-src/
COPY ./.conanrc /pktvisor-src/

WORKDIR /pktvisor-src

RUN \
    conan profile detect -f && \
    cd build/ && \
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=./cmake/conan_provider.cmake .. && \
    make all -j 4

FROM golang:latest AS gobuild
COPY golang/ /src/
WORKDIR /src/
COPY --from=cppbuild /pktvisor-src/golang/pkg/client/version.go /src/pkg/client/version.go
RUN go build -o pktvisor-cli cmd/pktvisor-cli/main.go

FROM ubuntu:noble AS runtime

ENV RUNTIME_DEPS "curl ca-certificates wget"

RUN \
    apt-get update && \
    apt-get upgrade --yes && \
    apt-get install --yes --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt
    
#create dir and download geo db
RUN mkdir /geo-db
RUN cd /geo-db && wget https://github.com/orb-community/geo-asn-database/raw/main/asn.mmdb.gz
RUN cd /geo-db && wget https://github.com/orb-community/geo-asn-database/raw/main/city.mmdb.gz

RUN mkdir /iana
COPY --from=cppbuild /pktvisor-src/src/tests/fixtures/pktvisor-port-service-names.csv /iana/custom-iana.csv

COPY --from=cppbuild /pktvisor-src/build/bin/pktvisord /usr/local/sbin/pktvisord
COPY --from=cppbuild /pktvisor-src/build/bin/crashpad_handler /usr/local/sbin/crashpad_handler
COPY --from=cppbuild /pktvisor-src/build/bin/pktvisor-reader /usr/local/sbin/pktvisor-reader
COPY --from=gobuild /src/pktvisor-cli /usr/local/bin/pktvisor-cli
COPY ./docker/entry-cp.sh /entry-cp.sh
COPY ./docker/run.sh /run.sh
RUN chmod a+x /entry-cp.sh
RUN chmod a+x /run.sh

ENTRYPOINT [ "/entry-cp.sh" ]


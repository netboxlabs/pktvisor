#!/bin/sh
# Runtime launcher for pktvisord in the Alpine image. The static musl
# build excludes crashpad, so no --cp-* flags are passed.
shift
pktvisord \
    --default-geo-city "/geo-db/city.mmdb" \
    --default-geo-asn "/geo-db/asn.mmdb" \
    --default-service-registry "/iana/custom-iana.csv" \
    "$@" &
echo $! > /var/run/pktvisord.pid

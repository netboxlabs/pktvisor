#!/bin/sh
# Entry point for the Alpine-based pktvisor image. POSIX sh (no bash) and
# no crashpad — the static musl binaries are built without crashpad support.
set -e

export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

trapeze() {
    printf "\rFinishing container.."
    exit 0
}
trap trapeze INT

if [ $# -eq 0 ]; then
    echo "No arguments provided: specify either 'pktvisor-cli', 'pktvisor-reader' or 'pktvisord'. Try:"
    echo "docker run netboxlabs/pktvisor:develop-alpine pktvisor-cli -h"
    echo "docker run netboxlabs/pktvisor:develop-alpine pktvisor-reader --help"
    echo "docker run netboxlabs/pktvisor:develop-alpine pktvisord --help"
    exit 1
fi

BINARY="$1"
if [ "$BINARY" = 'pktvisor' ]; then
    BINARY='pktvisor-cli'
fi
if [ "$BINARY" = 'pktvisor-pcap' ]; then
    BINARY='pktvisor-reader'
fi

if [ "$BINARY" = 'pktvisor-cli' ]; then
    sleep 1
fi

if [ "$BINARY" = 'pktvisord' ]; then
    cd /geo-db/
    if [ -f "asn.mmdb.gz" ]; then
        gzip -d asn.mmdb.gz
        gzip -d city.mmdb.gz
    fi
    cd /
    while true; do
        if [ ! -f "/var/run/pktvisord.pid" ]; then
            nohup /run.sh "$@" &
            sleep 2
            if [ -d "/nohup.out" ]; then
                tail -f /nohup.out &
            fi
        else
            PID=$(cat /var/run/pktvisord.pid)
            if [ ! -d "/proc/$PID" ]; then
                echo "$PID is not running"
                rm /var/run/pktvisord.pid
                exit 1
            fi
            sleep 10
        fi
    done
else
    shift
    exec "$BINARY" "$@"
fi

#!/bin/bash
# this is the entry point to the docker container, and is only used there
set -e

export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

trapeze () {

printf "\rFinishing container.."
exit 0
}

trap trapeze SIGINT

if [ $# -eq 0 ]; then
  echo "No arguments provided: specify either 'pktvisor-cli', 'pktvisor-reader' or 'pktvisord'. Try:"
  echo "docker run netboxlabs/pktvisor pktvisor-cli -h"
  echo "docker run netboxlabs/pktvisor pktvisor-reader --help"
  echo "docker run netboxlabs/pktvisor pktvisord --help"
  exit 1
fi

# backwards compatibility
BINARY="$1"
if [ "$BINARY" = 'pktvisor' ]; then
  BINARY='pktvisor-cli'
fi

if [ "$BINARY" = 'pktvisor-pcap' ]; then
  BINARY='pktvisor-reader'
fi

# Add sleep to allow tty to be ready for Docker when using -it
if [ "$BINARY" = 'pktvisor-cli' ]; then
  sleep 1
fi

# if binary is pktvisord
if [ "$BINARY" = 'pktvisord' ]; then
  # extract geodb
  cd /geo-db/
  if [ -f "asn.mmdb.gz" ]; then
    gzip -d asn.mmdb.gz
    gzip -d city.mmdb.gz
  fi
  cd /
  # eternal loop
  while true
  do
    # pid file dont exist
    if [ ! -f "/var/run/pktvisord.pid"  ]; then
      # running pktvisord in background
      nohup /run.sh "$@" &
      sleep 2
      if [ -d "/nohup.out" ]; then
         tail -f /nohup.out &
      fi
    else
      PID=$(cat /var/run/pktvisord.pid)
      if [ ! -d "/proc/$PID" ]; then
         # stop container
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

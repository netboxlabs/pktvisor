ARG PKTVISOR_TAG=latest
FROM telegraf:1.16.2 as telegraf

FROM netboxlabs/pktvisor:${PKTVISOR_TAG}

COPY --from=telegraf /usr/bin/telegraf /usr/local/bin/telegraf

RUN  apt-get update \
  && apt-get install -y runit-init dnsutils \
  && rm -rf /var/lib/apt \
  && mkdir -p /etc/runit/ \
  && mkdir -p /etc/telegraf/ \
  && rm -rf /etc/service/*

COPY misc/run-telegraf.sh /etc/service/telegraf/run
COPY misc/run-pktvisord.sh /etc/service/pktvisord/run
COPY misc/run-dig.sh /etc/service/dig/run
COPY misc/entrypoint /usr/local/bin/entrypoint

ENTRYPOINT /usr/local/bin/entrypoint

ARG PKTVISOR_TAG=latest
FROM grafana/agent:latest AS agent

FROM netboxlabs/pktvisor:${PKTVISOR_TAG}

COPY --from=agent /bin/grafana-agent /usr/local/bin/agent

RUN  apt-get update \
  && apt-get install -y runit \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /etc/runit/ \
  && mkdir -p /etc/agent/ \
  && mkdir -p /etc/agent/data \
  && rm -rf /etc/service/*

COPY files/run-grafana-agent.sh /etc/service/agent/run
COPY files/run-pktvisord.sh /etc/service/pktvisord/run
COPY files/entrypoint /usr/local/bin/entrypoint

ENTRYPOINT /usr/local/bin/entrypoint

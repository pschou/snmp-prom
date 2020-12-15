ARG ARCH="amd64"
ARG OS="linux"
FROM scratch
LABEL description="Very simple reliable ssl forwarder, built in golang" owner="dockerfile@paulschou.com"

EXPOSE      9070
ADD ./snmp-prom "/snmp-prom"
ENTRYPOINT  [ "/snmp-prom" ]

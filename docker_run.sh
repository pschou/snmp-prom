#!/bin/bash

docker run -d --name snmp-prom --rm \
  -p 9070:9070 \
  --name=snmp-prom \
  -v /home/stats/snmp-prom:/config \
  -v /etc/pki:/etc/pki \
  pschou/snmp-prom:0.1 -tls=false -config /config/config_full.yml


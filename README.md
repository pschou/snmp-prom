# snmp-prom
Simple SNMP exporter for Prometheus

This app is a generic SNMP-Prometheus tool that allows Prometheus & Grafana to query any SNMP endpoint to display live metrics.

![Grafana Page](/screens/SNMP_Screen.PNG?raw=true "Grafana example of SNMP metrics")

# Command line arguments:
```
 Usage of ./snmp-prom:
  -ca string
        File to load with ROOT CAs - reloaded every minute by adding any new entries (default "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  -cert string
        File to load with CERT - automatically reloaded every minute (default "/etc/pki/server.pem")
  -config string
        YML configuration file (default "config.yml")
  -debug
        Verbose output
  -key string
        File to load with KEY - automatically reloaded every minute (default "/etc/pki/server.pem")
  -listen string
        Listen address for forwarder (default ":9070")
  -secure-server
        Enforce TLS 1.2 on server side (default true)
  -tls
        Enable listener TLS (use -tls=true)
  -verify-server
        Verify or disable server certificate check (default true)
```

# Getting Started
First you must build a config file to tell snmp-prom how to query your SNMP devices.  To start let's first look at what a config.yml looks likt then we'll break it down:

```
version: 1
interval: 15s
- name: router
  enabled: true
  host: 10.12.0.1
  port: 161
  protocol: udp

  # Authentication details
  community: public
  trap-version: 2
  auth-type: none
  auth: SHA1
  enc: AES
  auth-password: authpass
  enc-password: encpass

  labels:
    identity: .1.3.6.1.2.1.1.5.0
    model: .1.3.6.1.2.1.1.1.0

  status:
    uptime: .1.3.6.1.2.1.1.3.0

  groupings:
  - group: interfaces
    priority: true
    labels:
      name: .1.3.6.1.2.1.31.1.1.1.1
    status:
      ifInErrors: .1.3.6.1.2.1.2.2.1.14
      ifOutErrors: .1.3.6.1.2.1.2.2.1.20
      ifHighSpeed: .1.3.6.1.2.1.31.1.1.1.15
      ifHCOutOctets: .1.3.6.1.2.1.31.1.1.1.10
      ifHCInOctets: .1.3.6.1.2.1.31.1.1.1.6
  - group: wireless
    labels:
      radio_name: .1.3.6.1.4.1.14988.1.1.1.2.1.20
    status:
      signal_strength: .1.3.6.1.4.1.14988.1.1.1.2.1.3
      tx_signal_strength: .1.3.6.1.4.1.14988.1.1.1.2.1.19
      tx_bytes: .1.3.6.1.4.1.14988.1.1.1.2.1.4
      rx_bytes: .1.3.6.1.4.1.14988.1.1.1.2.1.5
```

## General Section
- interval:  The default interval for all devices, unless specified (default: 15s)

## Device Sub-tree
Properties fields:
- name:  What to name this device (device_name in prometheus)
- enabled:  Either true or false, enables queries to the device
- host:  The actual network location of the device, such as an IP address
- port:  If SNMP is on a non-standard port, set it here  (default: 161)
- protocol:  Sets SNMP to use either udp or tcp (default: udp)
- community:  The SNMP community to connect with
- version:  The version of SNMP to use for connection: 1, 2c, 3
- copy-oids-from:  Use an already set device as a template for this device
- interval:  How often to query this device (default: see general section default)

Authentication Fields (v3):
- username:  The authenticated UserName, if not set then authentication is not attempted
- auth-protocol:  Which Protocol to use for authentication: none, md5, sha, sha224, sha256, sha384, sha512
- auth-password:  The "Password" to use for authentication, if set authentication is attempted
- priv-protocol:  Which Protocol to use for privacy: none, des, aes, aes192, aes192c, aes256, aes256c
- priv-password:  The "Password" to use for privacy, if set privacy is used

Prometheus Labels and Status:
- labels:  Dynamic labels to be passed to prometheus (such as contact: 1.1...)
- status:  Dynamic numeric values to be passed to prometheus (such as cpu_load: 1.1...)
- static-labels:  Static "label: value" to be passed to prometheus for metrics selection
- static-status:  Static numeric values "up: 1" to be passed to prometheus for metric values

### Device Groupings Sub-tree
This is where groups of metrics are defined, such as details by interface port, routing table entries, connected wireless users, any anything else exposed by the SNMP endpoint.
- group:  The name of the group to be appended to the metric name
- priority:  When querying devices, and you want compare metrics between devices (such as interface throughput), this sets this group as priority and should be queried first, on the interval mark
- query-metrics:  Include metric details about this group query, such as time of query and latency
- labels:  Dynamic labels to be passed to prometheus (such as port: 1.1...)
- status:  Dynamic numeric values to be passed to prometheus (such as tx_bytes: 1.1...)
- static-labels:  Static "label: value" to be passed to prometheus for group labeling
- static-status:  Static numeric values "up: 1" to be passed to prometheus for group values


# snmp-prom
Simple SNMP exporter for Prometheus

This app is a generic SNMP-Prometheus tool that allows Prometheus & Grafana to query any SNMP endpoint to display live metrics.

# Motiviation
When I surveyed the SNMP tools out for managing my routers and switches, I found an apparent lack of interest in metrics that were usable for detecting line loss. Means of mention came close, like Cacti and SolarWinds, but these were either limited by customizability or their windowing method.  By being limited by the windowing method: this means if two routers communicate over a distance-- If one router sees increased flow starting at 12 seconds after the minute and then stops 24 seconds after the minute; this measurement should be seen from the output of one router and should as closely match the input at the alternate router.  Of course, the latency will cause the edges not to match up exactly, but the idea is just this.  If I take the router A interface metric tied to the router B interface, I want to take an A-B and have a zero-sum, or as close to zero as possible.  If optics on sending versus received see a substantial loss (say due to weather or line stress), I will see this over time. 

When I saw all of this, I saw this as a challenge: to write one that just worked.  Hence you have SNMP-prom.

Whats addressed:

1.	Temporal windows that match up everywhere - see above
2.	OID table, keep it simple - we don’t need to look up MIBs for defined OIDs
3.	Prometheus time - between routers every metric has to have the same metric time

Things not considered and could be reviewed in the future:

1.	The sending and receiving time sides on a link could be pre/post collected by microseconds offset to more precisely match interface statistics
2.	Leap Second Rot – Currently, rounding up or down to the minute is being done by the unix timestamp and thus this tool.  One should not double count/drop a second during the leap second, but what can be done?


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
# Verification it is working
Once you have setup the configuration file and pointed the `snmp-prom` executable `-config`, you can browse with either your web browser or a cURL command to verify that the metrics are being collected by going to http://localhost:9070

```
$ curl localhost:9070
snmp_interfaces_ifInErrors{router="server_room",identity="TEST",model="RouterOS RB750GL",oid_index="3",name="ether3",device_host="10.12.254.192",device_name="test"} 0 1608261300000
snmp_interfaces_ifInErrors{oid_index="4",device_name="test",identity="TEST",router="server_room",model="RouterOS RB750GL",device_host="10.12.254.192",name="bridge1"} 0 1608261300000
...
```


# Getting Started
First you must build a config file to tell snmp-prom how to query your SNMP devices.  To start let's first look at what a config.yml looks likt then we'll break it down:

```
interval: 1m
devices:
- name: router
  enabled: true
  host: 10.12.0.1
  port: 161
  protocol: udp

  # Authentication details
  community: public
  version: 3
	username: secure
  auth-protocol: SHA1
  priv-protocol: AES
  auth-password: authpass
  priv-password: encpass

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
		index: mac
    labels:
      radio_name: .1.3.6.1.4.1.14988.1.1.1.2.1.20
    status:
      signal_strength: .1.3.6.1.4.1.14988.1.1.1.2.1.3
      tx_signal_strength: .1.3.6.1.4.1.14988.1.1.1.2.1.19
      tx_bytes: .1.3.6.1.4.1.14988.1.1.1.2.1.4
      rx_bytes: .1.3.6.1.4.1.14988.1.1.1.2.1.5

- name: betaRouter
  enabled: true
  host: 10.12.30.1
  port: 161
  protocol: udp
  copy-oids-from: router

  # Authentication details, only auth, no privacy
  community: public
  version: 3
	username: seal
  auth-protocol: SHA1
  auth-password: authpass2
```

The idea above is that a "template" is created with the name of the kind of device to provile, and these can then be loaded up in the subsequent device entries.  This can save updating the entire device list when the template changes can be applied to all.

To get the list of MIBs for a device, you'll need to walk the available mibs
```
$ snmpwalk 10.12.0.1 -c public -v 2c -Cc
...
IP-MIB::ip.21.1.1.10.12.254.10 = IpAddress: 10.12.254.10
IP-MIB::ip.21.1.1.10.12.254.111 = IpAddress: 10.12.254.111
...
```


Then get the numerical value of said MIB:
```
$ snmptranslate -On CISCO-RHINO-MIB::ciscoLS1010ChassisFanLed
 .1.3.6.1.4.1.9.5.11.1.1.12
```

This numerical version is then tabulated in the yaml file as the prometheus metric / label.  Please note that while picking the label names, you may only use names that have the regex equvilant: `[a-zA-Z_][a-zA-Z0-9_]*`, basically this means only an alpha initial character (preferrably lower case) and then alpha numeric after that with underscores `_`... hyphens `-` are NOT allowed (as they can be confused as a math operator).

## General Section
- interval:  The default interval for all devices, unless specified (default: 1m)
- push:  URLs of POST endpoints to push data -- for https endpoints, mTLS is attempted if cert/key is specified on the command line

Note: A good prometheus push gateway endpoint can be found here: https://github.com/pschou/prom-collector

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
- index:  Parse the subtree oid into oid label values:  route, mac, hex, ipv4, ipv6
- labels:  Dynamic labels to be passed to prometheus (such as port: 1.1...)
- status:  Dynamic numeric values to be passed to prometheus (such as tx_bytes: 1.1...)
- static-labels:  Static "label: value" to be passed to prometheus for group labeling
- static-status:  Static numeric values "up: 1" to be passed to prometheus for group values


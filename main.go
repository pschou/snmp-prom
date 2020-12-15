//
//  Simple SNMP exporter - With just a basic YAML file, you can connect any SNMP device to Prometheus
//
//  Written by Paul Schou  github@paulschou.com  December 2020
//
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	g "github.com/gosnmp/gosnmp"
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

type Config struct {
	Push     string `yaml:"push"`
	Interval string `default:"15s" yaml:"interval"`
	Devices  []struct {
		Name         string             `yaml:"name"`
		Host         string             `yaml:"host"`
		Port         uint16             `default:161 yaml:"port"`
		Protocol     string             `default:"udp" yaml:"protocol"`
		Community    string             `default:"public" yaml:"community"`
		UserName     string             `yaml:"username"`
		AuthProto    string             `yaml:"auth-protocol"`
		AuthPassword string             `yaml:"auth-password"`
		PrivProto    string             `yaml:"priv-protocol"`
		PrivPassword string             `yaml:"priv-password"`
		Version      string             `yaml:"version"`
		Interval     string             `yaml:"interval"`
		Enabled      bool               `yaml:"enabled" default:true`
		CopyFrom     string             `yaml:"copy-oids-from"`
		StaticLabels map[string]string  `yaml:"static-labels"`
		StaticStatus map[string]float64 `yaml:"static-status"`
		Labels       map[string]string  `yaml:"labels"`
		Status       map[string]string  `yaml:"status"`
		Groupings    []ConfigGroup      `yaml:"groupings"`
		nextRun      int64
		minLatency   int64
	} `yaml:"devices"`
}
type ConfigGroup struct {
	Group        string             `yaml:"group"`
	Priority     bool               `yaml:"priority"`
	QueryMetrics bool               `yaml:"query-metrics"`
	Labels       map[string]string  `yaml:"labels"`
	Status       map[string]string  `yaml:"status"`
	StaticLabels map[string]string  `yaml:"static-labels"`
	StaticStatus map[string]float64 `yaml:"static-status"`
	latency      int64
}

var deviceMetrics []string
var config Config

var keyFile = ""
var certFile = ""
var keypair *tls.Certificate
var keypair_count = 0
var keypair_mu sync.RWMutex
var rootFile = ""
var root_count = 0
var rootpool *x509.CertPool
var certs_loaded = make(map[string]bool, 0)
var debug = false

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Simple SNMP prometheus exporter, written by Paul Schou github@paulschou.com in December 2020\nAll rights reserved, personal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.\n\n Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var listen = flag.String("listen", ":9070", "Listen address for forwarder")
	var config_file = flag.String("config", "config.yml", "YML configuration file")
	var cert_file = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute")
	var key_file = flag.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute")
	var root_file = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries")
	var verify_server = flag.Bool("verify-server", true, "Verify or disable server certificate check")
	var secure_server = flag.Bool("secure-server", true, "Enforce TLS 1.2 on server side")
	var tls_enabled = flag.Bool("tls", false, "Enable listener TLS (use -tls=true)")
	var verbose = flag.Bool("debug", false, "Verbose output")
	flag.Parse()

	var err error
	debug = *verbose

	keyFile = *key_file
	certFile = *cert_file
	rootFile = *root_file

	if *tls_enabled {
		rootpool = x509.NewCertPool()
		loadKeys()
		go func() {
			ticker := time.NewTicker(time.Minute)
			for {
				select {
				case <-ticker.C:
					loadKeys()
				}
			}
		}()
	}

	yamlFile, err := ioutil.ReadFile(*config_file)
	if err != nil {
		log.Fatal("Cannot read config file", *config_file, err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal("Invalid config file format", err)
	}
	if config.Interval == "" {
		config.Interval = "15s"
	}

	for i, dev := range config.Devices {
		if dev.CopyFrom != "" {
			src_i := 0
			for src, src_dev := range config.Devices {
				if src_dev.Name == dev.CopyFrom {
					src_i = src
					break
				}
			}
			if src_i >= 0 {
				config.Devices[i].StaticLabels = config.Devices[src_i].StaticLabels
				config.Devices[i].StaticStatus = config.Devices[src_i].StaticStatus
				config.Devices[i].Labels = config.Devices[src_i].Labels
				config.Devices[i].Status = config.Devices[src_i].Status
				config.Devices[i].Groupings = config.Devices[src_i].Groupings
			} else {
				log.Println("Warning: copy-from source device", dev.CopyFrom, "missing for", dev.Name)
			}
		}

		if debug {
			log.Println(fmt.Sprintf("#conf %s: %+v", dev.Name, config.Devices[i]))
		}

		if dev.Interval == "" {
			config.Devices[i].Interval = config.Interval
		}

	}

	var l net.Listener
	if *tls_enabled {
		var config tls.Config
		if *secure_server {
			config = tls.Config{RootCAs: rootpool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootpool, InsecureSkipVerify: *verify_server == false,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			config = tls.Config{RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: *verify_server == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		config.Rand = rand.Reader
		if debug {
			fmt.Println("TLS Listening on", *listen)
		}
		if l, err = tls.Listen("tcp", *listen, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if debug {
			fmt.Println("Listening on", *listen)
		}
		if l, err = net.Listen("tcp", *listen); err != nil {
			log.Fatal(err)
		}
	}

	// make the query interval be unique to each device
	// Collect metrics from snmp endpoints
	deviceMetrics = make([]string, len(config.Devices))
	for i, dev := range config.Devices {
		if dev.Enabled {

			interval, err := time.ParseDuration(dev.Interval)
			if err != nil {
				log.Fatal("Device "+dev.Name+": Query interval not a valid time", err)
			}
			go func(i int, interval time.Duration) {
				runInterval := interval.Nanoseconds()
				config.Devices[i].nextRun = ((time.Now().UnixNano()+2e9)/runInterval + 1) * runInterval
				time.Sleep(time.Duration(config.Devices[i].nextRun-time.Now().UnixNano()-1.2e9) * time.Nanosecond)
				if debug {
					log.Println(" Next run for device "+config.Devices[i].Name+":", time.Unix(config.Devices[i].nextRun/1e9, 0))
				}
				go collectDev(i)
				for _ = range time.Tick(interval) {
					config.Devices[i].nextRun = ((time.Now().UnixNano()+2e9)/runInterval + 1) * runInterval
					if debug {
						log.Println(" Next run for device "+config.Devices[i].Name+":", time.Unix(config.Devices[i].nextRun/1e9, 0))
					}
					go collectDev(i)
				}
			}(i, interval)
		}
	}

	// Expose prometheus endpoint for querying metrics
	http.HandleFunc("/metrics", ServeMetrics)
	http.Serve(l, nil)
}

func getSNMP(i int) *g.GoSNMP {
	params := &g.GoSNMP{
		Port:               161,
		Transport:          "udp",
		Community:          "public",
		Version:            g.Version2c,
		Timeout:            time.Duration(5) * time.Second,
		Retries:            0,
		ExponentialTimeout: false,
		MaxOids:            50,
		MaxRepetitions:     10,
		Target:             config.Devices[i].Host,
		Context:            context.TODO(),
	}
	if debug {
		params.Logger = log.New(os.Stdout, "", 0)
	}
	switch ver := config.Devices[i].Version; ver {
	case "1":
		params.Version = g.Version1
	case "2c":
		params.Version = g.Version2c
	case "3":
		params.Version = g.Version3

		if config.Devices[i].UserName != "" {
			params.SecurityModel = g.UserSecurityModel
			if config.Devices[i].AuthPassword == "" {
				params.MsgFlags = g.NoAuthNoPriv
			} else {
				if config.Devices[i].PrivPassword == "" {
					params.MsgFlags = g.AuthNoPriv
				} else {
					params.MsgFlags = g.AuthPriv
				}
				sec := &g.UsmSecurityParameters{
					UserName:                 config.Devices[i].UserName,
					AuthenticationProtocol:   g.SHA,
					AuthenticationPassphrase: config.Devices[i].AuthPassword,
					PrivacyProtocol:          g.AES,
					PrivacyPassphrase:        config.Devices[i].PrivPassword,
				}

				switch p := strings.ToLower(config.Devices[i].AuthProto); p {
				case "none":
					sec.AuthenticationProtocol = g.NoAuth
				case "md5":
					sec.AuthenticationProtocol = g.MD5
				case "sha":
					sec.AuthenticationProtocol = g.SHA
				case "sha224":
					sec.AuthenticationProtocol = g.SHA224
				case "sha256":
					sec.AuthenticationProtocol = g.SHA256
				case "sha384":
					sec.AuthenticationProtocol = g.SHA384
				case "sha512":
					sec.AuthenticationProtocol = g.SHA512
				}

				switch p := strings.ToLower(config.Devices[i].PrivProto); p {
				case "none":
					sec.PrivacyProtocol = g.NoPriv
				case "des":
					sec.PrivacyProtocol = g.DES
				case "aes":
					sec.PrivacyProtocol = g.AES
				case "aes192":
					sec.PrivacyProtocol = g.AES192
				case "aes192c":
					sec.PrivacyProtocol = g.AES192C
				case "aes256":
					sec.PrivacyProtocol = g.AES256
				case "aes256c":
					sec.PrivacyProtocol = g.AES256C
				}
				params.SecurityParameters = sec
			}
		}

	}
	if config.Devices[i].Community != "" {
		params.Community = config.Devices[i].Community
	}
	if config.Devices[i].Port > 0 {
		params.Port = config.Devices[i].Port
	}
	if config.Devices[i].Protocol != "" {
		params.Transport = config.Devices[i].Protocol
	}

	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect failed on device "+config.Devices[i].Name+", err: %v", err)
	}
	return params
}

func loadKeys() {
	keypair_mu.RLock()
	defer keypair_mu.RUnlock()

	tmp_key, err_k := tls.LoadX509KeyPair(certFile, keyFile)
	if err_k != nil {
		if keypair == nil {
			log.Fatalf("failed to loadkey pair: %s %s %s", certFile, keyFile, err_k)
		}
		keypair_count++
		log.Println("WARNING: Cannot load keypair (cert/key)", certFile, keyFile, "attempt:", keypair_count)
		if keypair_count > 10 {
			log.Fatalf("failed to refresh pair: %s %s %s", certFile, keyFile, err_k)
		}
	} else {
		if debug {
			log.Println("Loaded keypair", certFile, keyFile)
		}
		keypair = &tmp_key
		keypair_count = 0
	}

	err_r := LoadCertficatesFromFile(rootFile)
	if err_r != nil {
		if rootpool == nil {
			log.Fatalf("failed to load CA: %s %s", rootFile, err_r)
		}
		root_count++
		log.Println("WARNING: Cannot load CA file", rootFile, "attempt:", root_count)
		if root_count > 10 {
			log.Fatalf("failed refresh CA: %s %s", rootFile, err_r)
		}
	} else {
		if debug {
			log.Println("Loaded CA", rootFile)
		}
		root_count = 0
	}
}

func LoadCertficatesFromFile(path string) error {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("warning: error parsing CA cert", err)
				continue
			}
			t := fmt.Sprintf("%v%v", cert.SerialNumber, cert.Subject)
			if _, ok := certs_loaded[t]; !ok {
				if debug {
					fmt.Println(" Adding CA:", cert.Subject)
				}
				rootpool.AddCert(cert)
				certs_loaded[t] = true
			}
		}
		raw = rest
	}

	return nil
}

func ServeMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "SNMP-Prom Exporter - Written by Paul Schou snmp-prom@paulschou.com; Copyright Dec 2020 - All rights reserved; Licensed for Personal Use Only")
	w.Header().Add("Cache-Control:", "no-store, no-cache")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("X-XSS-Protection", "1; mode=block")

	count := 0
	for i, dev := range config.Devices {
		if dev.Enabled {
			count++
			fmt.Fprintf(w, "# Device %s (%s)\n", config.Devices[i].Name, config.Devices[i].Host)
			if len(deviceMetrics[i]) == 0 {
				fmt.Fprintf(w, "# ...waiting for next query interval mark\n")
			} else {
				fmt.Fprintf(w, "%s\n", deviceMetrics[i])
			}
		}
	}
	if count == 0 {
		fmt.Fprintf(w, "# No devices have been configured or enabled\n")
	}

}

func mkList(oids []string, devOids map[string]string) []string {
	for _, v := range devOids {
		found := false
		for _, t := range oids {
			if t == v {
				found = true
			}
		}
		if found == false {
			v = strings.SplitN(v, " ", 2)[0]
			oids = append(oids, v)
		}
	}
	return oids
}

func collectDev(idev int) {
	query_chan := make(chan *g.SnmpPacket) // preallocate channels for parallelism

	for i, group := range config.Devices[idev].Groupings {
		if group.Priority {
			snmp := getSNMP(idev)
			defer snmp.Conn.Close()
			if debug {
				fmt.Println("#", config.Devices[idev].Name, "setting up query for", group.Group)
			}
			if config.Devices[idev].minLatency == 0 {
				// zero latency is impossible, so let's put something as a temporary placeholder
				config.Devices[idev].minLatency = 200000
			}

			go func(idev int, i int) {
				oids := mkList([]string{}, config.Devices[idev].Groupings[i].Status)
				oids = mkList(oids, config.Devices[idev].Groupings[i].Labels)
				if debug {
					fmt.Println("#", config.Devices[idev].Name, "waiting", config.Devices[idev].nextRun-time.Now().UnixNano(), "net latency adjustment", config.Devices[idev].minLatency)
					fmt.Println("to send query for", config.Devices[idev].Groupings[i].Group)
				}
				var send time.Time
				var reply time.Time
				time.Sleep(time.Duration(config.Devices[idev].nextRun-time.Now().UnixNano()-config.Devices[idev].minLatency/2) * time.Nanosecond)

				result, err := snmp.GetBulk(oids, 0, 50)
				if err != nil {
					if debug {
						fmt.Println("Error in GetBulk on", config.Devices[idev].Name, err)
					}
					query_chan <- nil
					return
				}

				if &result.Latency != nil {
					config.Devices[idev].Groupings[i].latency = result.Latency.Nanoseconds()
				}

				if debug {
					fmt.Println("#", config.Devices[idev].Name, "sent query for ", config.Devices[idev].Groupings[i].Group, "at", send, "with latency adjustment")
					fmt.Println("#", config.Devices[idev].Name, " MISSED the mark by ---> ", (send.UnixNano() - config.Devices[idev].nextRun - config.Devices[idev].minLatency/2), "nanoseconds  <---")
				}
				if debug {
					fmt.Println("#", config.Devices[idev].Name, "reply query for ", config.Devices[idev].Groupings[i].Group, "at", reply)
				}
				if err != nil {
					log.Println(Red+"Error during oid fetch for interface status host:", config.Devices[idev].Host, err, Reset)
				}
				query_chan <- result
			}(idev, i)
		}
	}
	group_data := make([](*g.SnmpPacket), len(config.Devices[idev].Groupings))
	for i, _ := range config.Devices[idev].Groupings {
		if config.Devices[idev].Groupings[i].Priority {
			group_data[i] = <-query_chan
			if group_data[i] == nil {
				return
			}
		}
	}

	snmp := getSNMP(idev)
	defer snmp.Conn.Close()
	snmp.Retries = 3
	snmp.Timeout = time.Duration(3) * time.Second

	// Setup output details / target
	runTime := config.Devices[idev].nextRun / 1e6
	outData := bytes.Buffer{}
	defer func(idev int, outData *bytes.Buffer) {
		deviceMetrics[idev] = outData.String()
	}(idev, &outData)

	//dev_query := make(chan *g.SnmpPacket)
	//func() {
	time.Sleep(80 * time.Millisecond) // * time.Nanosecond)
	oids := mkList([]string{}, config.Devices[idev].Status)
	oids = mkList(oids, config.Devices[idev].Labels)
	dev_data, err := snmp.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err != nil {
		log.Println("Error during oid fetch for device status host:", config.Devices[idev].Host, err)
		return
	}
	minLatency := dev_data.Latency.Nanoseconds()
	//dev_query <- result
	//}()
	//dev_data := <-dev_query
	if dev_data == nil {
		log.Println("No data returned for dev query, skipping host", config.Devices[idev].Host, err)
		return
	}

	// PARSE Labels for device
	dev_labels := make(map[string]string)
	dev_labels["device_host"] = config.Devices[idev].Host
	dev_labels["device_name"] = config.Devices[idev].Name
	for lbl, value := range config.Devices[idev].StaticLabels {
		dev_labels[lbl] = fmt.Sprintf("%v", value)
	}
	for lbl, oid := range config.Devices[idev].Labels {
		oid_dot, oid_type := dotEnd(oid)
		for _, variable := range dev_data.Variables {
			if oid_dot == variable.Name+"." {
				dev_labels[lbl] = fmt.Sprintf("%s", printPDU(variable, oid_type))
			}
		}
	}

	// PARSE Stats for device
	for lbl, value := range config.Devices[idev].StaticStatus {
		outData.WriteString(fmt.Sprintf("snmp_%s{%s} %v %d\n", lbl, promLabels(dev_labels), value, runTime))
	}
	for stat, oid := range config.Devices[idev].Status {
		oid_dot, oid_type := dotEnd(oid)
		for _, variable := range dev_data.Variables {
			if oid_dot == variable.Name+"." {
				outData.WriteString(fmt.Sprintf("snmp_%s{%s} %v %d\n", stat, promLabels(dev_labels), printPDU(variable, oid_type), runTime))
			}
		}
	}

	// Loop over the rest of the non priority groups
	for i, group := range config.Devices[idev].Groupings {
		time.Sleep(80 * time.Millisecond)
		if !group.Priority {
			if debug {
				fmt.Println("#", config.Devices[idev].Name, "setting up query for", group.Group)
			}

			oids := mkList([]string{}, config.Devices[idev].Groupings[i].Status)
			oids = mkList(oids, config.Devices[idev].Groupings[i].Labels)
			if debug {
				fmt.Println("#", config.Devices[idev].Name, "sending query for", config.Devices[idev].Groupings[i].Group, oids)
			}

			result, err := snmp.GetBulk(oids, 0, 50) // Get() accepts up to g.MAX_OIDS
			if err != nil {
				continue
			}
			config.Devices[idev].Groupings[i].latency = result.Latency.Nanoseconds()

			if err != nil {
				log.Println("Error during oid fetch for interface status host:", config.Devices[idev].Host, err)
			}
			group_data[i] = result
		}
	}

	for i, grp := range config.Devices[idev].Groupings {
		if minLatency == 0 {
			minLatency = grp.latency
		} else if grp.latency < minLatency && grp.latency > 0 {
			minLatency = grp.latency
		}
		parse(dev_labels, grp, group_data[i], runTime, &outData)
	}
	config.Devices[idev].minLatency = minLatency

	if minLatency > 0 {
		outData.WriteString(fmt.Sprintf("snmp_latency_seconds{%s} %v %d\n", promLabels(dev_labels), float64(minLatency)/1e9, runTime))
	}
}

func dotEnd(str string) (string, string) {
	temp := strings.SplitN(str, " ", 2)
	if len(temp) == 1 {
		return strings.TrimSuffix(temp[0], ".") + ".", ""
	} else {
		return strings.TrimSuffix(temp[0], ".") + ".", temp[1]
	}
}
func printPDU(pdu g.SnmpPDU, oid_type string) string {
	switch pdu.Type {
	case g.OctetString:
		b := pdu.Value.([]byte)
		switch strings.TrimSpace(oid_type) {
		case "hex":
			return hex.EncodeToString(b)
		default:
			return fmt.Sprintf("%s", string(b))
		}
	case g.Counter64:
		return fmt.Sprintf("%v", g.ToBigInt(pdu.Value))
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
	return ""
}

func parse(dev_labels map[string]string, group ConfigGroup, data *g.SnmpPacket, runTime int64, outData *bytes.Buffer) {
	if data == nil {
		if debug {
			log.Println(Yellow+"Empty SNMP reply on", dev_labels["device_name"], "- Cannot parse data for group", group.Group, Reset)
		}
		return
	}
	// PARSE Labels for Group
	common_labels := make(map[string]string)
	for lbl, value := range group.StaticLabels {
		common_labels[lbl] = fmt.Sprintf("%v", value)
	}
	group_labels := make(map[string]map[string]string)
	for lbl, oid := range group.Labels {
		oid_dot, oid_type := dotEnd(oid)
		for _, variable := range data.Variables {
			if strings.HasPrefix(variable.Name, oid_dot) {
				t := variable.Name[(len(oid_dot)):]
				//fmt.Println("oid=", oid, "name=", variable.Name, "t=", t, "lbl=", lbl, fmt.Sprintf("%v", variable.Value), index)
				if _, ok := group_labels[t]; !ok {
					group_labels[t] = make(map[string]string)
				}
				group_labels[t][lbl] = printPDU(variable, oid_type)
			}
		}
	}

	// PARSE Stats for Group
	for t, _ := range group_labels {
		for lbl, value := range group.StaticStatus {
			outData.WriteString(fmt.Sprintf("snmp_%s_%s{%s} %v %d\n", group.Group, lbl, promLabels(dev_labels, common_labels, group_labels[t]), value, runTime))
		}
	}
	//index := make(map[string]int)
	for stat, oid := range group.Status {
		oid_dot, oid_type := dotEnd(oid)
		for _, variable := range data.Variables {
			if strings.HasPrefix(variable.Name, oid_dot) {
				t := variable.Name[len(oid_dot):]
				if _, ok := group_labels[t]; !ok {
					group_labels[t] = make(map[string]string)
				}
				group_labels[t]["oid_index"] = t
				outData.WriteString(fmt.Sprintf("snmp_%s_%s{%s} %v %d\n", group.Group, stat, promLabels(dev_labels, common_labels, group_labels[t]), printPDU(variable, oid_type), runTime))
			}
		}
		if group.QueryMetrics {
			outData.WriteString(fmt.Sprintf("snmp_%s_%s_query_time{%s} %v %d\n", group.Group, stat, promLabels(dev_labels), runTime/1000, runTime))
			outData.WriteString(fmt.Sprintf("snmp_%s_%s_query_latency{%s} %v %d\n", group.Group, stat, promLabels(dev_labels),
				float64(data.Latency)/1e9, runTime))
		}
	}
}

func promLabels(lbl ...map[string]string) string {
	s := make(map[string]string)
	for _, in := range lbl {
		for k, v := range in {
			s[k] = fmt.Sprintf("%v", v)
		}
	}
	out := []string{}
	for k, v := range s {
		out = append(out, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(out, ",")
}

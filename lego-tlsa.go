package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/challenge/dns01"
	"github.com/miekg/dns"
)

var version = "dev"

type mapping map[string]struct {
	tcpports, udpports []int
}

var (
	pathStr    string
	nameserver string
	mappings   = mapping{
		"influx": {tcpports: []int{8888}},
		"ha":     {tcpports: []int{8123}},
		"webcam": {tcpports: []int{8080}},
		"router": {tcpports: []int{809}},
		"git":    {tcpports: []int{443}},
		"pve":    {tcpports: []int{8006}},

		"mx":         {tcpports: []int{25}},
		"mx1":        {tcpports: []int{25}},
		"mx2":        {tcpports: []int{25}},
		"mx3":        {tcpports: []int{25}},
		"mx4":        {tcpports: []int{25}},
		"smtp":       {tcpports: []int{25, 465, 587}},
		"submission": {tcpports: []int{587}},
		"smtps":      {tcpports: []int{465}},
		"pop3":       {tcpports: []int{110, 995}},
		"pop3s":      {tcpports: []int{995}},
		"imap":       {tcpports: []int{143, 993}},
		"imaps":      {tcpports: []int{993}},
		"news":       {tcpports: []int{119, 563}},
		"nntp":       {tcpports: []int{119, 563}},
		"nntps":      {tcpports: []int{563}},
		"ldap":       {tcpports: []int{389, 636}},
		"ldaps":      {tcpports: []int{636}},
		"ftp":        {tcpports: []int{21, 990}},
		"ftps":       {tcpports: []int{990}},
		"openvpn":    {tcpports: []int{943}, udpports: []int{1194}},
	}
	fqdn2zone  = map[string]string{}
	ttl        = flag.Uint("ttl", 86400, "TTL of the TLSA RR's")
	verbose    = flag.Bool("verbose", false, "Verbose logging")
	dryrun     = flag.Bool("dry_run", false, "Dry run, do not actually send dns updates")
	hasversion = flag.Bool("version", false, "Show verion information")
)

func (m *mapping) String() string {
	return ""
}

// Decode a string like <prefix>:<port>{t|u}[,<port>{t|u}]*[;<prefix>:<port>{t|u}[,<port>{t|u}]*]*
func (m *mapping) Set(s string) error {
	if m == nil {
		*m = make(mapping)
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' }) {
		names := strings.SplitN(part, ":", 2)
		if len(names) != 2 {
			return fmt.Errorf("missing name")
		}
		ports := struct{ tcpports, udpports []int }{}
		for _, port := range strings.FieldsFunc(names[1], func(r rune) bool { return r == ',' }) {
			porttype := port[len(port)-1:]
			if val, err := strconv.Atoi(port[:len(port)-1]); err != nil {
				return fmt.Errorf("invalid port number")
			} else {
				switch porttype {
				case "t":
					ports.tcpports = append(ports.tcpports, val)
				case "u":
					ports.udpports = append(ports.udpports, val)
				default:
					return fmt.Errorf("missing 't' or 'u' suffix")
				}
			}
		}
		(*m)[names[0]] = ports
	}
	return nil
}

func unFqdn(fqdn string) string {
	n := len(fqdn)
	if n > 0 && fqdn[n-1] == '.' {
		return fqdn[:n-1]
	}
	return fqdn
}

func ParseSingleDomain(domain string, zone2RR *map[string][]dns.RR) error {
	certBytes, err := ioutil.ReadFile(path.Join(pathStr, "certificates", domain+".crt"))
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return fmt.Errorf("Pem decode did not yield a valid block. Is the certificate in the right format?")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if *verbose {
		fmt.Printf("dnsnames %v\n", cert.DNSNames)
	}

	// Build a list of zones from the domains
	for _, name := range cert.DNSNames {
		fqdn := dns.Fqdn(name)
		zone, err := dns01.FindZoneByFqdnCustom(fqdn, []string{nameserver})
		if err != nil {
			return fmt.Errorf("ERROR: unable to determine zone for %q: %v", name, err)
		}

		// Do some very adhoc mapping from certname to ports and register tlsa entries for them
		tcp_ports := []int{443}
		udp_ports := []int{}
		if ports, ok := mappings[dns.SplitDomainName(name)[0]]; ok {
			tcp_ports = ports.tcpports
			udp_ports = ports.udpports
		}
		for _, port := range tcp_ports {
			tlsa := fmt.Sprintf("_%d._tcp.%s", port, fqdn)
			rr := &dns.TLSA{Hdr: dns.RR_Header{Name: tlsa, Class: dns.ClassINET, Ttl: uint32(*ttl)}}
			rr.Sign(3, 0, 1, cert)
			(*zone2RR)[zone] = append((*zone2RR)[zone], rr)
		}
		for _, port := range udp_ports {
			tlsa := fmt.Sprintf("_%d._udp.%s", port, fqdn)
			rr := &dns.TLSA{Hdr: dns.RR_Header{Name: tlsa, Class: dns.ClassINET, Ttl: uint32(*ttl)}}
			rr.Sign(3, 0, 1, cert)
			(*zone2RR)[zone] = append((*zone2RR)[zone], rr)
		}
	}

	return nil
}

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Could not determine current working directory. Please pass --path.")
		os.Exit(1)
	}
	defaultPath := path.Join(cwd, ".lego")
	flag.StringVar(&pathStr, "path", defaultPath, "Path to get the certificates from")
	flag.Var(&mappings, "mappings", "Add special prefix to port numbers mapping according to <prefix>:<port>{t|u}[,<port>{t|u}]*[;<prefix>:<port>{t|u}[,<port>{t|u}]*]*. E.g. influx:8888t")
	flag.Parse()

	if *hasversion {
		fmt.Printf("lego-tlsa version %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	nameserver = os.Getenv("RFC2136_NAMESERVER")
	if nameserver == "" {
		fmt.Println("RFC2136 nameserver missing")
		os.Exit(1)
	}
	// Append the default DNS port if none is specified.
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			nameserver = net.JoinHostPort(nameserver, "53")
		} else {
			fmt.Printf("Error adding port %s: %v\n", nameserver, err)
			os.Exit(1)
		}
	}
	tsigAlgorithm := os.Getenv("RFC2136_TSIG_ALGORITHM")
	tsigKey := os.Getenv("RFC2136_TSIG_KEY")
	tsigSecret := os.Getenv("RFC2136_TSIG_SECRET")
	if tsigAlgorithm == "" {
		tsigAlgorithm = dns.HmacMD5
	}

	rrMap := make(map[string][]dns.RR, len(flag.Args()))
	for _, d := range flag.Args() {
		if err = ParseSingleDomain(d, &rrMap); err != nil {
			fmt.Printf("Error processing %s: %v\n", d, err)
			os.Exit(1)
		}
	}
	if *verbose {
		for k, v := range rrMap {
			for _, vv := range v {
				fmt.Printf("rrMap[%v]: %+v\n", k, vv)
			}
		}
	}

	// Setup a dns client
	c := dns.Client{SingleInflight: true}
	// TSIG authentication / msg signing
	if len(tsigKey) > 0 && len(tsigSecret) > 0 {
		c.TsigSecret = map[string]string{dns.Fqdn(tsigKey): tsigSecret}
	}
	for zone, rrs := range rrMap {
		// Only one zone per update, so create a new dynamic update packet per zone
		m := new(dns.Msg)
		m.SetUpdate(zone)
		m.RemoveRRset(rrs)
		m.Insert(rrs)
		if len(tsigKey) > 0 && len(tsigSecret) > 0 {
			m.SetTsig(dns.Fqdn(tsigKey), tsigAlgorithm, 300, time.Now().Unix())
		}

		// Send the query
		if *verbose || *dryrun {
			fmt.Printf("msg=%v\n", m)
		}
		if !*dryrun {
			reply, _, err := c.Exchange(m, nameserver)
			if err != nil {
				fmt.Printf("DNS update failed: %v\n", err)
			}
			if reply != nil && reply.Rcode != dns.RcodeSuccess {
				fmt.Printf("DNS update failed. Server replied: %s\n", dns.RcodeToString[reply.Rcode])
			}
		}
	}
}

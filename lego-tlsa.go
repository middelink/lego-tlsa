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
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xenolf/lego/acme"
)

var (
	pathStr    string
	nameserver string
	fqdn2zone  = map[string]string{}
	ttl        = flag.Uint("ttl", 86400, "TTL of the TLSA RR's")
	verbose    = flag.Bool("verbose", false, "Verbose logging")
)

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

	// Build a list of zones from the domains
	for _, name := range cert.DNSNames {
		fqdn := dns.Fqdn(name)
		zone, err := acme.FindZoneByFqdn(fqdn, []string{nameserver})
		if err != nil {
			return fmt.Errorf("ERROR: unable to determine zone for %q: %v", name, err)
		}

		// Do some very adhoc mapping from certname to ports and register tlsa entries for them
		tcp_ports := []int{443}
		udp_ports := []int{}
		switch dns.SplitDomainName(name)[0] {
		case "smtp", "submission", "smtps":
			tcp_ports = []int{25, 587, 465}
		case "pop3", "pop3s":
			tcp_ports = []int{110, 995}
		case "imap", "imaps":
			tcp_ports = []int{143, 993}
		case "news", "nntp", "nntps":
			tcp_ports = []int{119, 563}
		case "ldap", "ldaps":
			tcp_ports = []int{389, 636}
		case "ftp", "ftps":
			tcp_ports = []int{21, 990}
		case "router":
			tcp_ports = []int{809}
		case "openvpn":
			tcp_ports = []int{943}
			udp_ports = []int{1194}
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

	if *verbose {
		fmt.Printf("dnsnames %v\n", cert.DNSNames)
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
	flag.Parse()

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
		fmt.Printf("rrMap %v\n", rrMap)
	}
	//os.Exit(0)

	// Setup a dns client
	c := new(dns.Client)
	c.SingleInflight = true
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
		if *verbose {
			fmt.Printf("msg=%v\n", m)
		}
		reply, _, err := c.Exchange(m, nameserver)
		if err != nil {
			fmt.Printf("DNS update failed: %v\n", err)
		}
		if reply != nil && reply.Rcode != dns.RcodeSuccess {
			fmt.Printf("DNS update failed. Server replied: %s\n", dns.RcodeToString[reply.Rcode])
		}
	}
}

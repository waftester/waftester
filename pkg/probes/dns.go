// Package probes - DNS and network resolution
package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSResult contains DNS resolution results
type DNSResult struct {
	Host       string     `json:"host"`
	IPs        []string   `json:"ips,omitempty"`
	IPv4       []string   `json:"ipv4,omitempty"`
	IPv6       []string   `json:"ipv6,omitempty"`
	CNAME      string     `json:"cname,omitempty"`
	CNAMEChain []string   `json:"cname_chain,omitempty"`
	MX         []MXRecord `json:"mx,omitempty"`
	NS         []string   `json:"ns,omitempty"`
	TXT        []string   `json:"txt,omitempty"`
	ASN        *ASNInfo   `json:"asn,omitempty"`
	PTR        []string   `json:"ptr,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// MXRecord represents an MX DNS record
type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// ASNInfo contains ASN information
type ASNInfo struct {
	Number       int    `json:"number"`
	Organization string `json:"organization"`
	Country      string `json:"country,omitempty"`
	Registry     string `json:"registry,omitempty"`
}

// DNSProber probes DNS records
type DNSProber struct {
	Timeout   time.Duration
	Resolvers []string
}

// NewDNSProber creates a new DNS prober with defaults
func NewDNSProber() *DNSProber {
	return &DNSProber{
		Timeout: 5 * time.Second,
	}
}

// Resolve performs comprehensive DNS resolution
func (d *DNSProber) Resolve(ctx context.Context, host string) *DNSResult {
	result := &DNSResult{
		Host: host,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: d.Timeout}
			if len(d.Resolvers) > 0 {
				return dialer.DialContext(ctx, network, d.Resolvers[0]+":53")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}

	// Resolve A and AAAA records
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err == nil {
		for _, ip := range ips {
			result.IPs = append(result.IPs, ip.IP.String())
			if ip.IP.To4() != nil {
				result.IPv4 = append(result.IPv4, ip.IP.String())
			} else {
				result.IPv6 = append(result.IPv6, ip.IP.String())
			}
		}
	}

	// Resolve CNAME
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" && cname != host+"." {
		result.CNAME = strings.TrimSuffix(cname, ".")
		// Follow CNAME chain
		result.CNAMEChain = d.followCNAMEChain(ctx, resolver, host, 10)
	}

	// Resolve MX
	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil {
		for _, mx := range mxRecords {
			result.MX = append(result.MX, MXRecord{
				Host:     strings.TrimSuffix(mx.Host, "."),
				Priority: mx.Pref,
			})
		}
	}

	// Resolve NS
	nsRecords, err := resolver.LookupNS(ctx, host)
	if err == nil {
		for _, ns := range nsRecords {
			result.NS = append(result.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// Resolve TXT (limited to first few)
	txtRecords, err := resolver.LookupTXT(ctx, host)
	if err == nil {
		for i, txt := range txtRecords {
			if i >= 5 { // Limit to 5 TXT records
				break
			}
			result.TXT = append(result.TXT, txt)
		}
	}

	// Reverse DNS (PTR) for first IP
	if len(result.IPv4) > 0 {
		ptrs, err := resolver.LookupAddr(ctx, result.IPv4[0])
		if err == nil {
			for _, ptr := range ptrs {
				result.PTR = append(result.PTR, strings.TrimSuffix(ptr, "."))
			}
		}
	}

	// ASN lookup for first IP
	if len(result.IPv4) > 0 {
		result.ASN = d.lookupASN(ctx, resolver, result.IPv4[0])
	}

	return result
}

// followCNAMEChain follows CNAME records to build a chain
func (d *DNSProber) followCNAMEChain(ctx context.Context, resolver *net.Resolver, host string, maxDepth int) []string {
	var chain []string
	current := host

	for i := 0; i < maxDepth; i++ {
		cname, err := resolver.LookupCNAME(ctx, current)
		if err != nil || cname == "" || cname == current+"." {
			break
		}
		cname = strings.TrimSuffix(cname, ".")
		if cname == current {
			break
		}
		chain = append(chain, cname)
		current = cname
	}

	return chain
}

// lookupASN performs ASN lookup using DNS
func (d *DNSProber) lookupASN(ctx context.Context, resolver *net.Resolver, ip string) *ASNInfo {
	// Use Team Cymru's DNS-based ASN lookup
	// Reverse the IP and query origin.asn.cymru.com
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil
	}

	// Reverse the IP octets
	reversed := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com",
		parts[3], parts[2], parts[1], parts[0])

	txtRecords, err := resolver.LookupTXT(ctx, reversed)
	if err != nil || len(txtRecords) == 0 {
		return nil
	}

	// Parse the response: "ASN | IP | Country | Registry | Date"
	txt := txtRecords[0]
	fields := strings.Split(txt, "|")
	if len(fields) < 3 {
		return nil
	}

	asn := &ASNInfo{}
	if _, err := fmt.Sscanf(strings.TrimSpace(fields[0]), "%d", &asn.Number); err != nil {
		return nil
	}

	if len(fields) > 2 {
		asn.Country = strings.TrimSpace(fields[2])
	}
	if len(fields) > 3 {
		asn.Registry = strings.TrimSpace(fields[3])
	}

	// Get ASN name
	asnQuery := fmt.Sprintf("AS%d.asn.cymru.com", asn.Number)
	asnTxt, err := resolver.LookupTXT(ctx, asnQuery)
	if err == nil && len(asnTxt) > 0 {
		asnFields := strings.Split(asnTxt[0], "|")
		if len(asnFields) > 4 {
			asn.Organization = strings.TrimSpace(asnFields[4])
		}
	}

	return asn
}

// ResolveIP is a simple IP resolution helper
func ResolveIP(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result, nil
}

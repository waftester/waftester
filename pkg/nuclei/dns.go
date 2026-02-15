package nuclei

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSRequest represents a DNS query in a template.
type DNSRequest struct {
	ID         string      `yaml:"id,omitempty"`
	Name       string      `yaml:"name"`              // Domain to query (supports {{variables}})
	Type       string      `yaml:"type"`              // A, AAAA, CNAME, MX, NS, TXT, SOA, PTR
	Class      string      `yaml:"class,omitempty"`   // IN (default)
	Resolver   string      `yaml:"resolver,omitempty"` // Custom DNS resolver address
	Recursion  bool        `yaml:"recursion"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// executeDNSRequest runs a DNS query and evaluates matchers/extractors.
func (e *Engine) executeDNSRequest(ctx context.Context, req *DNSRequest, vars map[string]string) (bool, map[string][]string, error) {
	extracted := make(map[string][]string)

	name := expandVariables(req.Name, vars)
	dnsType := strings.ToUpper(req.Type)
	if dnsType == "" {
		dnsType = "A"
	}

	// Build resolver
	resolver := net.DefaultResolver
	if req.Resolver != "" {
		resolverAddr := req.Resolver
		if !strings.Contains(resolverAddr, ":") {
			resolverAddr += ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		}
	}

	var answers []string
	var err error

	switch dnsType {
	case "A", "AAAA":
		var ips []string
		ips, err = resolver.LookupHost(ctx, name)
		if err == nil {
			for _, ip := range ips {
				parsed := net.ParseIP(ip)
				if parsed == nil {
					continue
				}
				if dnsType == "A" && parsed.To4() != nil {
					answers = append(answers, ip)
				} else if dnsType == "AAAA" && parsed.To4() == nil {
					answers = append(answers, ip)
				}
			}
		}
	case "CNAME":
		var cname string
		cname, err = resolver.LookupCNAME(ctx, name)
		if err == nil && cname != "" {
			answers = append(answers, cname)
		}
	case "MX":
		var mxs []*net.MX
		mxs, err = resolver.LookupMX(ctx, name)
		if err == nil {
			for _, mx := range mxs {
				answers = append(answers, fmt.Sprintf("%s %d", mx.Host, mx.Pref))
			}
		}
	case "NS":
		var nss []*net.NS
		nss, err = resolver.LookupNS(ctx, name)
		if err == nil {
			for _, ns := range nss {
				answers = append(answers, ns.Host)
			}
		}
	case "TXT":
		var txts []string
		txts, err = resolver.LookupTXT(ctx, name)
		if err == nil {
			answers = txts
		}
	case "PTR":
		var ptrs []string
		ptrs, err = resolver.LookupAddr(ctx, name)
		if err == nil {
			answers = ptrs
		}
	default:
		return false, extracted, fmt.Errorf("unsupported DNS type: %s", dnsType)
	}

	// Build response body from answers for matching
	body := strings.Join(answers, "\n")
	if err != nil {
		// DNS errors are not fatal; the error is part of the response
		body = err.Error()
	}

	respData := &ResponseData{
		StatusCode: len(answers), // Use answer count as pseudo status
		Body:       []byte(body),
	}

	condition := "or"
	if len(req.Matchers) > 0 && req.Matchers[0].Condition != "" {
		condition = req.Matchers[0].Condition
	}

	matched := evaluateMatchers(req.Matchers, condition, respData)

	for _, extractor := range req.Extractors {
		values := runExtractor(&extractor, respData)
		name := extractor.Name
		if name == "" {
			name = "extracted"
		}
		extracted[name] = append(extracted[name], values...)
	}

	return matched, extracted, nil
}

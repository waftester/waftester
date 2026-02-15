package nuclei

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/waftester/waftester/pkg/duration"
)

// DNSRequest represents a DNS query in a template.
type DNSRequest struct {
	ID                string      `yaml:"id,omitempty"`
	Name              string      `yaml:"name"`                         // Domain to query (supports {{variables}})
	Type              string      `yaml:"type"`                         // A, AAAA, CNAME, MX, NS, TXT, PTR
	Class             string      `yaml:"class,omitempty"`              // Parsed but unused — stdlib resolver uses IN only
	Resolver          string      `yaml:"resolver,omitempty"`           // Custom DNS resolver address
	Recursion         bool        `yaml:"recursion"`                    // Parsed but unused — stdlib resolver handles recursion
	MatchersCondition string      `yaml:"matchers-condition,omitempty"` // "and" or "or" (default: "or")
	Matchers          []Matcher   `yaml:"matchers,omitempty"`
	Extractors        []Extractor `yaml:"extractors,omitempty"`
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
				d := net.Dialer{Timeout: duration.DialTimeout}
				return d.DialContext(ctx, network, resolverAddr)
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
	if err != nil && len(answers) == 0 {
		// DNS lookup failed with no answers — report as error, not a matchable response
		return false, extracted, fmt.Errorf("dns lookup: %w", err)
	}

	respData := &ResponseData{
		Body: []byte(body),
	}

	condition := "or"
	if req.MatchersCondition != "" {
		condition = req.MatchersCondition
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

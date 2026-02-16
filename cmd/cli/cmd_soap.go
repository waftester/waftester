package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/soap"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// SOAP COMMAND - SOAP/WSDL Service Testing
// =============================================================================

func runSOAP() {
	ui.PrintCompactBanner()
	ui.PrintSection("SOAP/WSDL Service Tester")

	soapFlags := flag.NewFlagSet("soap", flag.ExitOnError)

	// Target options
	endpoint := soapFlags.String("endpoint", "", "SOAP service endpoint URL")
	endpointShort := soapFlags.String("u", "", "SOAP endpoint URL (shorthand)")
	wsdl := soapFlags.String("wsdl", "", "WSDL URL to parse")

	// Operation options
	listOperations := soapFlags.Bool("list", false, "List available operations from WSDL")
	operation := soapFlags.String("operation", "", "Operation/action to call")
	action := soapFlags.String("action", "", "SOAPAction header value")
	namespace := soapFlags.String("ns", "", "Operation namespace")

	// Request options
	data := soapFlags.String("d", "", "SOAP body content (XML)")
	dataFile := soapFlags.String("f", "", "File containing SOAP body content")
	headers := soapFlags.String("H", "", "Custom headers (key:value,key:value)")

	// Fuzzing options
	fuzz := soapFlags.Bool("fuzz", false, "Fuzz SOAP operations with attack payloads")
	payloadCategory := soapFlags.String("category", "xxe", "Payload category for fuzzing: xxe, sqli, xss")
	payloadDir := soapFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	templateDir := soapFlags.String("template-dir", defaults.TemplateDir, "Nuclei template directory")

	// Connection options
	timeout := soapFlags.Int("timeout", 30, "Request timeout in seconds")

	// Output options
	outputFile := soapFlags.String("o", "", "Output file (JSON)")
	jsonOutput := soapFlags.Bool("json", false, "Output in JSON format")
	verbose := soapFlags.Bool("v", false, "Verbose output")

	soapFlags.Parse(os.Args[2:])

	// Resolve nuclei template directory with embedded fallback.
	if resolved, err := templateresolver.ResolveNucleiDir(*templateDir); err == nil {
		*templateDir = resolved
	}

	// Get endpoint
	endpointURL := *endpoint
	if endpointURL == "" {
		endpointURL = *endpointShort
	}

	// WSDL parsing mode
	if *wsdl != "" && *listOperations {
		runSOAPWSDLList(*wsdl, *jsonOutput, *verbose, *timeout)
		return
	}

	// Need endpoint for other operations
	if endpointURL == "" {
		ui.PrintError("SOAP endpoint URL required")
		fmt.Println()
		fmt.Println("Usage: waf-tester soap -u <endpoint> [options]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester soap --wsdl https://example.com/service?wsdl --list")
		fmt.Println("  waf-tester soap -u https://example.com/service --operation GetUser -d '<GetUser><id>1</id></GetUser>'")
		fmt.Println("  waf-tester soap -u https://example.com/service --fuzz --category xxe")
		os.Exit(1)
	}

	if !*jsonOutput {
		ui.PrintConfigLine("Endpoint", endpointURL)
		if *operation != "" {
			ui.PrintConfigLine("Operation", *operation)
		}
		if *fuzz {
			ui.PrintConfigLine("Mode", "Fuzz SOAP Operations")
			ui.PrintConfigLine("Category", *payloadCategory)
		}
		fmt.Println()
	}

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	ctx, tCancel := context.WithTimeout(ctx, time.Duration(*timeout)*time.Second)
	defer tCancel()

	// Create SOAP client
	clientOpts := []soap.ClientOption{
		soap.WithTimeout(time.Duration(*timeout) * time.Second),
	}
	if *action != "" {
		clientOpts = append(clientOpts, soap.WithSOAPAction(*action))
	}
	if *namespace != "" {
		clientOpts = append(clientOpts, soap.WithNamespace(*namespace))
	}

	client := soap.NewClient(endpointURL, clientOpts...)

	// Execute requested operation
	switch {
	case *fuzz:
		runSOAPFuzz(ctx, client, endpointURL, *payloadDir, *templateDir, *payloadCategory, *outputFile, *jsonOutput)

	case *operation != "" || *data != "" || *dataFile != "":
		runSOAPCall(ctx, client, *operation, *action, *data, *dataFile, *headers, *jsonOutput, *verbose)

	default:
		ui.PrintError("Specify --operation, --fuzz, or --wsdl --list")
		os.Exit(1)
	}
}

func runSOAPWSDLList(wsdlURL string, jsonOutput, verbose bool, timeout int) {
	if !jsonOutput {
		ui.PrintConfigLine("WSDL", wsdlURL)
		fmt.Println()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	wsdlDef, err := soap.FetchAndParseWSDL(ctx, wsdlURL)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to parse WSDL: %v", err))
		os.Exit(1)
	}

	operations := wsdlDef.GetOperations()

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"wsdl":       wsdlURL,
			"operations": operations,
			"count":      len(operations),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection("Available Operations")
	for _, op := range operations {
		fmt.Printf("  • %s\n", op.Name)
		if verbose && op.SOAPAction != "" {
			fmt.Printf("    SOAPAction: %s\n", op.SOAPAction)
		}
		if verbose && op.Input != "" {
			fmt.Printf("    Input: %s\n", op.Input)
		}
	}
	fmt.Println()
	ui.PrintSuccess(fmt.Sprintf("Found %d operations", len(operations)))
}

func runSOAPCall(ctx context.Context, client *soap.Client, operation, action, data, dataFile, headers string, jsonOutput, verbose bool) {
	// Read body from file if specified
	body := data
	if dataFile != "" {
		fileData, err := os.ReadFile(dataFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to read data file: %v", err))
			os.Exit(1)
		}
		body = string(fileData)
	}

	// Parse custom headers
	customHeaders := make(map[string]string)
	if headers != "" {
		for _, kv := range strings.Split(headers, ",") {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) == 2 {
				customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	req := &soap.Request{
		Action:    action,
		Operation: operation,
		Body:      body,
		Headers:   customHeaders,
	}

	if verbose && !jsonOutput {
		ui.PrintConfigLine("Operation", operation)
		ui.PrintConfigLine("Action", action)
		fmt.Println()
	}

	resp, err := client.Call(req)
	if err != nil {
		ui.PrintError(fmt.Sprintf("SOAP call failed: %v", err))
		if resp != nil && resp.Fault != nil {
			ui.PrintError(fmt.Sprintf("Fault: %s - %s", resp.Fault.Code, resp.Fault.String))
		}
		os.Exit(1)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"status_code": resp.StatusCode,
			"body":        resp.Body,
			"fault":       resp.Fault,
			"latency_ms":  resp.Latency.Milliseconds(),
			"blocked":     resp.Blocked,
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection("Response")
	fmt.Println(resp.Body)
	fmt.Println()
	ui.PrintConfigLine("Status", fmt.Sprintf("%d", resp.StatusCode))
	ui.PrintConfigLine("Latency", resp.Latency.String())
	if resp.Blocked {
		ui.PrintWarning("Request appears to be blocked by WAF")
	}
	if resp.Fault != nil {
		ui.PrintWarning(fmt.Sprintf("SOAP Fault: %s", resp.Fault.String))
	}
}

func runSOAPFuzz(ctx context.Context, client *soap.Client, endpoint, payloadDir, templateDir, category string, outputFile string, jsonOutput bool) {
	type fuzzResult struct {
		Payload    string `json:"payload"`
		Category   string `json:"category"`
		StatusCode int    `json:"status_code"`
		Blocked    bool   `json:"blocked"`
		Fault      string `json:"fault,omitempty"`
		Latency    string `json:"latency"`
	}

	var results []fuzzResult

	// Get attack payloads from unified engine (JSON + Nuclei templates)
	payloads := getUnifiedFuzzPayloads(payloadDir, templateDir, category, 50, false)

	if !jsonOutput {
		ui.PrintConfigLine("Payloads", fmt.Sprintf("%d", len(payloads)))
		fmt.Println()
	}

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			break
		default:
		}

		// Wrap payload in SOAP body
		soapBody := fmt.Sprintf(`<TestOperation><value>%s</value></TestOperation>`, payload)

		req := &soap.Request{
			Body: soapBody,
		}

		resp, err := client.Call(req)

		fr := fuzzResult{
			Payload:  payload,
			Category: category,
		}

		if err != nil {
			fr.Blocked = true
		}

		if resp != nil {
			fr.StatusCode = resp.StatusCode
			fr.Blocked = resp.Blocked
			fr.Latency = resp.Latency.String()
			if resp.Fault != nil {
				fr.Fault = resp.Fault.String
			}
		}

		results = append(results, fr)

		if !jsonOutput {
			if fr.Blocked {
				ui.PrintWarning(fmt.Sprintf("[BLOCKED] %s", truncatePayload(payload, 60)))
			} else {
				fmt.Printf("[PASSED] %s\n", truncatePayload(payload, 60))
			}
		}
	}

	// Output results
	if outputFile != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results written to %s", outputFile))
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println()
		blocked := 0
		for _, r := range results {
			if r.Blocked {
				blocked++
			}
		}
		ui.PrintSection("Summary")
		ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", len(results)))
		ui.PrintConfigLine("Blocked", fmt.Sprintf("%d", blocked))
		ui.PrintConfigLine("Passed", fmt.Sprintf("%d", len(results)-blocked))
	}
}

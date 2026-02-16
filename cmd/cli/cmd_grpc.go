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
	"github.com/waftester/waftester/pkg/grpc"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// GRPC COMMAND - gRPC Service Testing
// =============================================================================

func runGRPC() {
	ui.PrintCompactBanner()
	ui.PrintSection("gRPC Service Tester")

	grpcFlags := flag.NewFlagSet("grpc", flag.ExitOnError)

	// Target options
	target := grpcFlags.String("target", "", "gRPC server address (host:port)")
	targetShort := grpcFlags.String("u", "", "gRPC server address (shorthand)")

	// Mode options
	listServices := grpcFlags.Bool("list", false, "List available services via reflection")
	describe := grpcFlags.String("describe", "", "Describe a specific service")
	call := grpcFlags.String("call", "", "Call a specific method (service/method)")
	fuzz := grpcFlags.Bool("fuzz", false, "Fuzz gRPC methods with attack payloads")

	// Call options
	data := grpcFlags.String("d", "{}", "Request data (JSON)")
	metadata := grpcFlags.String("metadata", "", "Metadata/headers (key:value,key:value)")

	// Fuzzing options
	payloadCategory := grpcFlags.String("category", "injection", "Payload category for fuzzing")
	payloadDir := grpcFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	templateDir := grpcFlags.String("template-dir", defaults.TemplateDir, "Nuclei template directory")

	// Connection options
	timeout := grpcFlags.Int("timeout", 30, "Connection timeout in seconds")

	// Output options
	outputFile := grpcFlags.String("o", "", "Output file (JSON)")
	jsonOutput := grpcFlags.Bool("json", false, "Output in JSON format")
	verbose := grpcFlags.Bool("v", false, "Verbose output")

	grpcFlags.Parse(os.Args[2:])

	// Resolve nuclei template directory with embedded fallback.
	if resolved, err := templateresolver.ResolveNucleiDir(*templateDir); err == nil {
		*templateDir = resolved
	}

	// Get target
	targetAddr := *target
	if targetAddr == "" {
		targetAddr = *targetShort
	}
	if targetAddr == "" {
		ui.PrintError("Target gRPC server address required")
		fmt.Println()
		fmt.Println("Usage: waf-tester grpc -u <host:port> [options]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester grpc -u localhost:50051 --list")
		fmt.Println("  waf-tester grpc -u localhost:50051 --describe grpc.health.v1.Health")
		fmt.Println("  waf-tester grpc -u localhost:50051 --call service.Method -d '{\"field\": \"value\"}'")
		fmt.Println("  waf-tester grpc -u localhost:50051 --fuzz --category sqli")
		os.Exit(1)
	}

	if !*jsonOutput {
		ui.PrintConfigLine("Target", targetAddr)
		if *listServices {
			ui.PrintConfigLine("Mode", "List Services")
		} else if *describe != "" {
			ui.PrintConfigLine("Mode", fmt.Sprintf("Describe: %s", *describe))
		} else if *call != "" {
			ui.PrintConfigLine("Mode", fmt.Sprintf("Call: %s", *call))
		} else if *fuzz {
			ui.PrintConfigLine("Mode", "Fuzz gRPC Methods")
			ui.PrintConfigLine("Category", *payloadCategory)
		}
		fmt.Println()
	}

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	ctx, tCancel := context.WithTimeout(ctx, time.Duration(*timeout)*time.Second)
	defer tCancel()

	// Create gRPC client
	client, err := grpc.NewClient(ctx, targetAddr, grpc.WithTimeout(time.Duration(*timeout)*time.Second))
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to connect: %v", err))
		os.Exit(1)
	}
	defer client.Close()

	ui.PrintSuccess("Connected to gRPC server")
	fmt.Println()

	// Execute requested operation
	switch {
	case *listServices:
		runGRPCList(ctx, client, *jsonOutput)

	case *describe != "":
		runGRPCDescribe(ctx, client, *describe, *jsonOutput)

	case *call != "":
		runGRPCCall(ctx, client, *call, *data, *metadata, *jsonOutput, *verbose)

	case *fuzz:
		runGRPCFuzz(ctx, client, *payloadDir, *templateDir, *payloadCategory, *outputFile, *jsonOutput)

	default:
		// Default to listing services
		runGRPCList(ctx, client, *jsonOutput)
	}
}

func runGRPCList(ctx context.Context, client *grpc.Client, jsonOutput bool) {
	services, err := client.ListServices(ctx)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to list services: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"services": services,
			"count":    len(services),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection("Available Services")
	for _, svc := range services {
		fmt.Printf("  • %s\n", svc)
	}
	fmt.Println()
	ui.PrintSuccess(fmt.Sprintf("Found %d services", len(services)))
}

func runGRPCDescribe(ctx context.Context, client *grpc.Client, serviceName string, jsonOutput bool) {
	desc, err := client.DescribeService(ctx, serviceName)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to describe service: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(desc, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection(fmt.Sprintf("Service: %s", desc.Name))
	fmt.Println()

	for _, method := range desc.Methods {
		streamInfo := ""
		if method.ClientStreaming && method.ServerStreaming {
			streamInfo = " [bidirectional stream]"
		} else if method.ClientStreaming {
			streamInfo = " [client stream]"
		} else if method.ServerStreaming {
			streamInfo = " [server stream]"
		}

		fmt.Printf("  %s%s\n", method.Name, streamInfo)
		fmt.Printf("    Input:  %s\n", method.InputType)
		fmt.Printf("    Output: %s\n", method.OutputType)
		fmt.Println()
	}

	ui.PrintSuccess(fmt.Sprintf("Found %d methods", len(desc.Methods)))
}

func runGRPCCall(ctx context.Context, client *grpc.Client, callSpec, data, metadata string, jsonOutput, verbose bool) {
	// Parse call spec: service/method or service.method
	parts := strings.Split(callSpec, "/")
	if len(parts) != 2 {
		parts = strings.Split(callSpec, ".")
		if len(parts) < 2 {
			ui.PrintError("Invalid call format. Use: service/method or package.service.method")
			os.Exit(1)
		}
	}

	// Parse metadata
	md := make(map[string]string)
	if metadata != "" {
		for _, kv := range strings.Split(metadata, ",") {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) == 2 {
				md[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if verbose {
		ui.PrintConfigLine("Call", callSpec)
		ui.PrintConfigLine("Data", data)
		if len(md) > 0 {
			ui.PrintConfigLine("Metadata", fmt.Sprintf("%v", md))
		}
	}

	// Make the call
	result, err := client.InvokeMethod(ctx, callSpec, []byte(data), md)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Call failed: %v", err))
		os.Exit(1)
	}

	if jsonOutput {
		fmt.Println(string(result.Response))
	} else {
		ui.PrintSection("Response")
		fmt.Println(string(result.Response))
		fmt.Println()
		ui.PrintConfigLine("Latency", result.Latency.String())
		if result.Blocked {
			ui.PrintWarning("Request appears to be blocked")
		}
	}
}

func runGRPCFuzz(ctx context.Context, client *grpc.Client, payloadDir, templateDir, category string, outputFile string, jsonOutput bool) {
	// First, discover services and methods
	services, err := client.ListServices(ctx)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to list services: %v", err))
		os.Exit(1)
	}

	type fuzzResult struct {
		Service  string `json:"service"`
		Method   string `json:"method"`
		Payload  string `json:"payload"`
		Blocked  bool   `json:"blocked"`
		Error    string `json:"error,omitempty"`
		Response string `json:"response,omitempty"`
	}

	var results []fuzzResult

	// Get attack payloads from unified engine (JSON + Nuclei templates)
	payloads := getUnifiedFuzzPayloads(payloadDir, templateDir, category, 50, false)

	if !jsonOutput {
		ui.PrintConfigLine("Services", fmt.Sprintf("%d", len(services)))
		ui.PrintConfigLine("Payloads", fmt.Sprintf("%d", len(payloads)))
		fmt.Println()
	}

	for _, svc := range services {
		// Skip reflection and health services
		if strings.Contains(svc, "reflection") || strings.Contains(svc, "grpc.health") {
			continue
		}

		desc, err := client.DescribeService(ctx, svc)
		if err != nil {
			continue
		}

		for _, method := range desc.Methods {
			for _, payload := range payloads {
				// Create fuzz request with payload
				fuzzData := fmt.Sprintf(`{"value": "%s"}`, payload)

				result, err := client.InvokeMethod(ctx, method.FullName, []byte(fuzzData), nil)

				fr := fuzzResult{
					Service: svc,
					Method:  method.Name,
					Payload: payload,
				}

				if err != nil {
					fr.Error = err.Error()
					fr.Blocked = true
				} else {
					fr.Blocked = result.Blocked
					if len(result.Response) < 1000 {
						fr.Response = string(result.Response)
					}
				}

				results = append(results, fr)

				if !jsonOutput && fr.Blocked {
					ui.PrintWarning(fmt.Sprintf("[BLOCKED] %s/%s: %s", svc, method.Name, truncatePayload(payload, 50)))
				} else if !jsonOutput && !fr.Blocked {
					fmt.Printf("[PASSED] %s/%s: %s\n", svc, method.Name, truncatePayload(payload, 50))
				}
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

func truncatePayload(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

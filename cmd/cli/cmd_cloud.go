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
	"github.com/waftester/waftester/pkg/cloud"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// CLOUD COMMAND - Cloud Resource Discovery
// =============================================================================

func runCloud() {
	ui.PrintCompactBanner()
	ui.PrintSection("Cloud Resource Discovery")

	cloudFlags := flag.NewFlagSet("cloud", flag.ExitOnError)

	// Target options
	domain := cloudFlags.String("domain", "", "Target domain to discover")
	domainShort := cloudFlags.String("d", "", "Target domain (shorthand)")
	orgName := cloudFlags.String("org", "", "Organization name for brute forcing")

	// Discovery options
	providers := cloudFlags.String("providers", "all", "Cloud providers: aws, azure, gcp, all")
	discoveryTypes := cloudFlags.String("types", "all", "Discovery types: storage, cdn, functions, api, all")
	wordlist := cloudFlags.String("w", "", "Custom wordlist for brute forcing")

	// Execution options
	concurrency := cloudFlags.Int("c", 50, "Concurrency level")
	rateLimit := cloudFlags.Float64("rl", 100, "Requests per second")
	timeout := cloudFlags.Int("timeout", 10, "Request timeout in seconds")

	// Passive options
	passiveOnly := cloudFlags.Bool("passive", false, "Passive discovery only (no active requests)")
	useCertTransparency := cloudFlags.Bool("ct", true, "Use Certificate Transparency logs")
	useDNS := cloudFlags.Bool("dns", true, "Use DNS enumeration")

	// Output options
	outputFile := cloudFlags.String("o", "", "Output file (JSON)")
	jsonOutput := cloudFlags.Bool("json", false, "Output in JSON format")
	verbose := cloudFlags.Bool("v", false, "Verbose output")

	cloudFlags.Parse(os.Args[2:])

	// Get domain
	targetDomain := *domain
	if targetDomain == "" {
		targetDomain = *domainShort
	}
	if targetDomain == "" && *orgName == "" {
		ui.PrintError("Domain or organization name required")
		fmt.Println()
		fmt.Println("Usage: waf-tester cloud -d <domain> [options]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester cloud -d example.com")
		fmt.Println("  waf-tester cloud -d example.com --providers aws,gcp")
		fmt.Println("  waf-tester cloud --org mycompany --types storage")
		os.Exit(1)
	}

	if !*jsonOutput {
		if targetDomain != "" {
			ui.PrintConfigLine("Domain", targetDomain)
		}
		if *orgName != "" {
			ui.PrintConfigLine("Organization", *orgName)
		}
		ui.PrintConfigLine("Providers", *providers)
		ui.PrintConfigLine("Types", *discoveryTypes)
		if *passiveOnly {
			ui.PrintConfigLine("Mode", "Passive only")
		}
		fmt.Println()
	}

	// Parse providers
	var providerList []cloud.Provider
	if *providers == "all" {
		providerList = []cloud.Provider{cloud.ProviderAWS, cloud.ProviderAzure, cloud.ProviderGCP}
	} else {
		for _, p := range strings.Split(*providers, ",") {
			switch strings.TrimSpace(strings.ToLower(p)) {
			case "aws":
				providerList = append(providerList, cloud.ProviderAWS)
			case "azure":
				providerList = append(providerList, cloud.ProviderAzure)
			case "gcp", "google":
				providerList = append(providerList, cloud.ProviderGCP)
			}
		}
	}

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	ctx, tCancel := context.WithTimeout(ctx, 30*time.Minute)
	defer tCancel()

	// Create discoverer
	discoverer := cloud.NewDiscoverer(cloud.DiscovererConfig{
		Concurrency:  *concurrency,
		RateLimit:    *rateLimit,
		Timeout:      time.Duration(*timeout) * time.Second,
		PassiveOnly:  *passiveOnly,
		UseCT:        *useCertTransparency,
		UseDNS:       *useDNS,
		WordlistPath: *wordlist,
	})

	// Run discovery
	results, err := discoverer.Discover(ctx, cloud.DiscoveryRequest{
		Domain:    targetDomain,
		OrgName:   *orgName,
		Providers: providerList,
		Types:     parseDiscoveryTypes(*discoveryTypes),
	})

	if err != nil {
		ui.PrintError(fmt.Sprintf("Discovery failed: %v", err))
		os.Exit(1)
	}

	// Output results
	if *outputFile != "" {
		data, marshalErr := json.MarshalIndent(results, "", "  ")
		if marshalErr != nil {
			ui.PrintError(fmt.Sprintf("Failed to marshal results: %v", marshalErr))
			os.Exit(1)
		}
		if err := os.WriteFile(*outputFile, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputFile))
		}
	}

	if *jsonOutput {
		data, marshalErr := json.MarshalIndent(results, "", "  ")
		if marshalErr != nil {
			ui.PrintError(fmt.Sprintf("Failed to marshal results: %v", marshalErr))
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	// Print results by provider
	for _, provider := range providerList {
		providerResults := filterByProvider(results.Resources, provider)
		if len(providerResults) == 0 {
			continue
		}

		ui.PrintSection(fmt.Sprintf("%s Resources", provider))

		for _, resource := range providerResults {
			statusIcon := "✓"
			statusColor := ui.Green
			if !resource.Accessible {
				statusIcon = "✗"
				statusColor = ui.Red
			}

			url := resource.URL
			if url == "" && len(resource.Endpoints) > 0 {
				url = resource.Endpoints[0]
			}

			fmt.Printf("  %s%s%s %s (%s)\n", statusColor, statusIcon, ui.Reset, url, resource.Type)
			if *verbose && len(resource.Details) > 0 {
				for k, v := range resource.Details {
					fmt.Printf("    %s: %s\n", k, v)
				}
			}
		}
		fmt.Println()
	}

	// Print summary
	ui.PrintSection("Summary")
	ui.PrintConfigLine("Total Resources", fmt.Sprintf("%d", len(results.Resources)))

	// Count by provider
	for _, provider := range providerList {
		count := len(filterByProvider(results.Resources, provider))
		if count > 0 {
			ui.PrintConfigLine(fmt.Sprintf("  %s", provider), fmt.Sprintf("%d", count))
		}
	}

	// Count accessible
	accessible := 0
	for _, r := range results.Resources {
		if r.Accessible {
			accessible++
		}
	}
	ui.PrintConfigLine("Accessible", fmt.Sprintf("%d", accessible))
}

func parseDiscoveryTypes(types string) []cloud.ResourceType {
	if types == "all" {
		return []cloud.ResourceType{
			cloud.TypeStorage,
			cloud.TypeCDN,
			cloud.TypeFunctions,
			cloud.TypeAPI,
			cloud.TypeDatabase,
		}
	}

	var result []cloud.ResourceType
	for _, t := range strings.Split(types, ",") {
		switch strings.TrimSpace(strings.ToLower(t)) {
		case "storage", "s3", "blob", "bucket":
			result = append(result, cloud.TypeStorage)
		case "cdn", "cloudfront":
			result = append(result, cloud.TypeCDN)
		case "functions", "lambda", "function":
			result = append(result, cloud.TypeFunctions)
		case "api", "gateway":
			result = append(result, cloud.TypeAPI)
		case "database", "db", "rds":
			result = append(result, cloud.TypeDatabase)
		}
	}
	return result
}

func filterByProvider(resources []*cloud.Resource, provider cloud.Provider) []*cloud.Resource {
	var result []*cloud.Resource
	for _, r := range resources {
		if r.Provider == provider {
			result = append(result, r)
		}
	}
	return result
}

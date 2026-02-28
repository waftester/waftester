// Package plugin provides a plugin system for custom scanners
package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sync"
)

// Scanner is the interface that all scanner plugins must implement
type Scanner interface {
	// Name returns the unique name of the scanner
	Name() string

	// Description returns a brief description of what the scanner does
	Description() string

	// Version returns the scanner version
	Version() string

	// Init initializes the scanner with configuration
	Init(config map[string]interface{}) error

	// Scan performs the scan on the target
	// Returns findings, metadata, and any error
	Scan(ctx context.Context, target *Target) (*ScanResult, error)

	// Cleanup releases any resources
	Cleanup() error
}

// Target represents a scan target
type Target struct {
	// URL is the target URL
	URL string `json:"url"`

	// Host is the target hostname
	Host string `json:"host"`

	// Port is the target port
	Port int `json:"port"`

	// Scheme is http or https
	Scheme string `json:"scheme"`

	// Path is the URL path
	Path string `json:"path"`

	// Method is the HTTP method
	Method string `json:"method"`

	// Headers are custom headers
	Headers map[string]string `json:"headers,omitempty"`

	// Body is the request body
	Body string `json:"body,omitempty"`

	// Cookies are custom cookies
	Cookies map[string]string `json:"cookies,omitempty"`

	// Metadata is custom metadata from discovery phase
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ScanResult represents the results from a scanner plugin
type ScanResult struct {
	// Scanner is the name of the scanner that produced this result
	Scanner string `json:"scanner"`

	// Findings are the discovered vulnerabilities
	Findings []Finding `json:"findings,omitempty"`

	// Info contains informational discoveries
	Info []InfoItem `json:"info,omitempty"`

	// Metadata is additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Error if the scan failed
	Error string `json:"error,omitempty"`

	// Duration of the scan
	DurationMs int64 `json:"duration_ms"`
}

// Finding represents a vulnerability finding
type Finding struct {
	// Title is a short description
	Title string `json:"title"`

	// Description is a detailed description
	Description string `json:"description,omitempty"`

	// Severity: critical, high, medium, low, info
	Severity string `json:"severity"`

	// Type is the vulnerability type (e.g., sqli, xss, ssrf)
	Type string `json:"type"`

	// Evidence is proof of the vulnerability
	Evidence string `json:"evidence,omitempty"`

	// Request is the raw request that triggered the finding
	Request string `json:"request,omitempty"`

	// Response is the raw response
	Response string `json:"response,omitempty"`

	// MatchedAt is where the vulnerability was found
	MatchedAt string `json:"matched_at,omitempty"`

	// Remediation is how to fix the issue
	Remediation string `json:"remediation,omitempty"`

	// References are links to more info
	References []string `json:"references,omitempty"`

	// CWE is the Common Weakness Enumeration ID
	CWE string `json:"cwe,omitempty"`

	// CVSS score (0-10)
	CVSS float64 `json:"cvss,omitempty"`

	// Metadata is additional data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// InfoItem represents informational data
type InfoItem struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

// Manager manages scanner plugins
type Manager struct {
	// Plugins maps plugin name to scanner
	Plugins map[string]Scanner

	// PluginDir is the directory to load plugins from
	PluginDir string

	mu sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(pluginDir string) *Manager {
	if pluginDir == "" {
		pluginDir = "plugins"
	}
	return &Manager{
		Plugins:   make(map[string]Scanner),
		PluginDir: pluginDir,
	}
}

// LoadPlugin loads a single plugin from a .so file
func (m *Manager) LoadPlugin(path string) error {
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look for the Scanner symbol
	sym, err := p.Lookup("Scanner")
	if err != nil {
		return fmt.Errorf("plugin %s does not export Scanner: %w", path, err)
	}

	// Type assert to Scanner interface
	scanner, ok := sym.(Scanner)
	if !ok {
		// Try pointer to Scanner
		scannerPtr, ok := sym.(*Scanner)
		if !ok {
			return fmt.Errorf("plugin %s Scanner does not implement Scanner interface", path)
		}
		scanner = *scannerPtr
	}

	m.mu.Lock()
	m.Plugins[scanner.Name()] = scanner
	m.mu.Unlock()

	return nil
}

// LoadAll loads all plugins from the plugin directory
func (m *Manager) LoadAll() error {
	if _, err := os.Stat(m.PluginDir); os.IsNotExist(err) {
		return nil // No plugins directory, not an error
	}

	files, err := filepath.Glob(filepath.Join(m.PluginDir, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to glob plugins: %w", err)
	}

	var errs []error
	for _, file := range files {
		if err := m.LoadPlugin(file); err != nil {
			errs = append(errs, err) // Keep trying other plugins
		}
	}

	return errors.Join(errs...)
}

// Register registers a built-in scanner
func (m *Manager) Register(scanner Scanner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Plugins[scanner.Name()] = scanner
}

// Get returns a scanner by name
func (m *Manager) Get(name string) (Scanner, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.Plugins[name]
	return s, ok
}

// List returns all registered scanner names
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.Plugins))
	for name := range m.Plugins {
		names = append(names, name)
	}
	return names
}

// Scan runs a single scanner on a target
func (m *Manager) Scan(ctx context.Context, scannerName string, target *Target) (*ScanResult, error) {
	scanner, ok := m.Get(scannerName)
	if !ok {
		return nil, fmt.Errorf("scanner not found: %s", scannerName)
	}

	return scanner.Scan(ctx, target)
}

// ScanAll runs all registered scanners on a target
func (m *Manager) ScanAll(ctx context.Context, target *Target) map[string]*ScanResult {
	m.mu.RLock()
	scanners := make([]Scanner, 0, len(m.Plugins))
	for _, s := range m.Plugins {
		scanners = append(scanners, s)
	}
	m.mu.RUnlock()

	results := make(map[string]*ScanResult)
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, scanner := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			result, err := s.Scan(ctx, target)
			if err != nil {
				result = &ScanResult{
					Scanner: s.Name(),
					Error:   err.Error(),
				}
			}

			mu.Lock()
			results[s.Name()] = result
			mu.Unlock()
		}(scanner)
	}

	wg.Wait()
	return results
}

// Cleanup releases resources for all plugins
func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, scanner := range m.Plugins {
		scanner.Cleanup()
	}
}

// PluginInfo returns info about a plugin
type PluginInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

// Info returns information about all loaded plugins
func (m *Manager) Info() []PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info := make([]PluginInfo, 0, len(m.Plugins))
	for _, scanner := range m.Plugins {
		info = append(info, PluginInfo{
			Name:        scanner.Name(),
			Description: scanner.Description(),
			Version:     scanner.Version(),
		})
	}
	return info
}

// LoadBuiltins loads all built-in scanner plugins
func (m *Manager) LoadBuiltins() error {
	// Built-in scanners are registered directly, not loaded from files
	// This method is a no-op if no built-ins are configured
	return nil
}

// LoadFromDirectory loads all plugins from a specific directory
func (m *Manager) LoadFromDirectory(dir string) error {
	if dir == "" {
		dir = m.PluginDir
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, not an error
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to glob plugins: %w", err)
	}

	var loadErr error
	for _, file := range files {
		if err := m.LoadPlugin(file); err != nil {
			loadErr = err
		}
	}

	return loadErr
}

// IsBuiltin returns whether a plugin is built-in or external
func (m *Manager) IsBuiltin(name string) bool {
	// For now, all plugins are external (loaded from .so files)
	// Built-in plugins would be registered differently
	return false
}

// GetPluginInfo returns info about a specific plugin
func (m *Manager) GetPluginInfo(name string) (*PluginInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scanner, ok := m.Plugins[name]
	if !ok {
		return nil, false
	}

	return &PluginInfo{
		Name:        scanner.Name(),
		Description: scanner.Description(),
		Version:     scanner.Version(),
	}, true
}

// pkg/ui/manifest.go - Execution manifest display for pre-run info
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ManifestItem represents a single item in the execution manifest
type ManifestItem struct {
	Label    string
	Value    interface{}
	Icon     string
	Emphasis bool // If true, highlight this item
}

// ExecutionManifest displays what will be executed before a run starts
type ExecutionManifest struct {
	Title       string
	Description string
	Items       []ManifestItem
	Writer      io.Writer
	BoxStyle    bool // If true, draw a box around the manifest
}

// NewExecutionManifest creates a new manifest with default settings
func NewExecutionManifest(title string) *ExecutionManifest {
	return &ExecutionManifest{
		Title:    title,
		Items:    make([]ManifestItem, 0),
		Writer:   os.Stdout,
		BoxStyle: true,
	}
}

// SetDescription sets a description line under the title
func (m *ExecutionManifest) SetDescription(desc string) *ExecutionManifest {
	m.Description = desc
	return m
}

// Add adds an item to the manifest
func (m *ExecutionManifest) Add(label string, value interface{}) *ExecutionManifest {
	m.Items = append(m.Items, ManifestItem{Label: label, Value: value})
	return m
}

// AddWithIcon adds an item with an icon
func (m *ExecutionManifest) AddWithIcon(icon, label string, value interface{}) *ExecutionManifest {
	m.Items = append(m.Items, ManifestItem{Icon: icon, Label: label, Value: value})
	return m
}

// AddEmphasis adds an emphasized item (highlighted)
func (m *ExecutionManifest) AddEmphasis(icon, label string, value interface{}) *ExecutionManifest {
	m.Items = append(m.Items, ManifestItem{Icon: icon, Label: label, Value: value, Emphasis: true})
	return m
}

// AddPayloadInfo adds payload count information (common pattern)
func (m *ExecutionManifest) AddPayloadInfo(count int, categories []string) *ExecutionManifest {
	m.AddEmphasis("📦", "Payloads", fmt.Sprintf("%d payloads loaded", count))
	if len(categories) > 0 {
		m.AddWithIcon("🏷️", "Categories", strings.Join(categories, ", "))
	}
	return m
}

// AddTargetInfo adds target count information
func (m *ExecutionManifest) AddTargetInfo(count int, sample string) *ExecutionManifest {
	if count == 1 {
		m.AddWithIcon("🎯", "Target", sample)
	} else {
		m.AddEmphasis("🎯", "Targets", fmt.Sprintf("%d targets", count))
		if sample != "" {
			m.AddWithIcon("", "First", sample)
		}
	}
	return m
}

// AddEstimate adds estimated time/request information
func (m *ExecutionManifest) AddEstimate(requests int, rateLimit float64) *ExecutionManifest {
	if rateLimit > 0 {
		estimatedSecs := float64(requests) / rateLimit
		var estimate string
		if estimatedSecs < 60 {
			estimate = fmt.Sprintf("~%.0fs", estimatedSecs)
		} else if estimatedSecs < 3600 {
			estimate = fmt.Sprintf("~%.1f min", estimatedSecs/60)
		} else {
			estimate = fmt.Sprintf("~%.1f hrs", estimatedSecs/3600)
		}
		m.AddWithIcon("⏱️", "Estimate", fmt.Sprintf("%s @ %.0f req/s", estimate, rateLimit))
	}
	return m
}

// AddConcurrency adds concurrency/rate info
func (m *ExecutionManifest) AddConcurrency(workers int, rateLimit float64) *ExecutionManifest {
	m.AddWithIcon("⚡", "Workers", fmt.Sprintf("%d concurrent", workers))
	if rateLimit > 0 {
		m.AddWithIcon("🚦", "Rate Limit", fmt.Sprintf("%.0f req/s", rateLimit))
	}
	return m
}

// Print displays the manifest
func (m *ExecutionManifest) Print() {
	if m.BoxStyle {
		m.printBoxed()
	} else {
		m.printSimple()
	}
}

// printBoxed displays manifest in a Unicode box
func (m *ExecutionManifest) printBoxed() {
	w := m.Writer

	// Calculate max width
	maxWidth := len(m.Title) + 4
	for _, item := range m.Items {
		width := len(item.Label) + len(fmt.Sprintf("%v", item.Value)) + 10
		if width > maxWidth {
			maxWidth = width
		}
	}
	if maxWidth > 70 {
		maxWidth = 70
	}
	if maxWidth < 50 {
		maxWidth = 50
	}

	// Box characters
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  ╔%s╗\n", strings.Repeat("═", maxWidth))
	
	// Title
	titlePadding := (maxWidth - len(m.Title)) / 2
	fmt.Fprintf(w, "  ║%s\033[1m%s\033[0m%s║\n",
		strings.Repeat(" ", titlePadding),
		m.Title,
		strings.Repeat(" ", maxWidth-titlePadding-len(m.Title)))

	// Description
	if m.Description != "" {
		descPadding := (maxWidth - len(m.Description)) / 2
		fmt.Fprintf(w, "  ║%s\033[2m%s\033[0m%s║\n",
			strings.Repeat(" ", descPadding),
			m.Description,
			strings.Repeat(" ", maxWidth-descPadding-len(m.Description)))
	}

	fmt.Fprintf(w, "  ╠%s╣\n", strings.Repeat("═", maxWidth))

	// Items
	for _, item := range m.Items {
		icon := item.Icon
		if icon != "" {
			icon = icon + " "
		}

		valueStr := fmt.Sprintf("%v", item.Value)
		
		// Apply emphasis styling
		if item.Emphasis {
			valueStr = fmt.Sprintf("\033[1;36m%s\033[0m", valueStr)
		}

		// Calculate padding
		labelPart := fmt.Sprintf("%s%s:", icon, item.Label)
		displayLen := len(icon) + len(item.Label) + 1 + len(fmt.Sprintf("%v", item.Value))
		padding := maxWidth - displayLen - 4
		if padding < 1 {
			padding = 1
		}

		fmt.Fprintf(w, "  ║  %s%s%s  ║\n", labelPart, strings.Repeat(" ", padding), valueStr)
	}

	fmt.Fprintf(w, "  ╚%s╝\n", strings.Repeat("═", maxWidth))
	fmt.Fprintln(w)
}

// printSimple displays manifest as simple key-value pairs
func (m *ExecutionManifest) printSimple() {
	w := m.Writer

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  \033[1m%s\033[0m\n", m.Title)
	if m.Description != "" {
		fmt.Fprintf(w, "  \033[2m%s\033[0m\n", m.Description)
	}
	fmt.Fprintln(w)

	for _, item := range m.Items {
		icon := item.Icon
		if icon != "" {
			icon = icon + " "
		}

		valueStr := fmt.Sprintf("%v", item.Value)
		if item.Emphasis {
			valueStr = fmt.Sprintf("\033[1;36m%s\033[0m", valueStr)
		}

		fmt.Fprintf(w, "    %s%s: %s\n", icon, item.Label, valueStr)
	}
	fmt.Fprintln(w)
}

// === Pre-built Manifest Templates ===

// AttackManifest creates a manifest for attack/scan operations
func AttackManifest(target string, payloadCount int, categories []string, concurrency int, rateLimit float64) *ExecutionManifest {
	m := NewExecutionManifest("EXECUTION MANIFEST")
	m.SetDescription("Attack surface and payload configuration")
	m.AddTargetInfo(1, target)
	m.AddPayloadInfo(payloadCount, categories)
	m.AddConcurrency(concurrency, rateLimit)
	m.AddEstimate(payloadCount, rateLimit)
	return m
}

// MultiTargetManifest creates a manifest for multi-target operations
func MultiTargetManifest(title string, targets []string, operation string) *ExecutionManifest {
	m := NewExecutionManifest(title)
	m.SetDescription(operation)
	
	sample := ""
	if len(targets) > 0 {
		sample = targets[0]
		if len(sample) > 50 {
			sample = sample[:47] + "..."
		}
	}
	m.AddTargetInfo(len(targets), sample)
	
	return m
}

// ScanManifest creates a manifest for comprehensive scan operations
func ScanManifest(target string, scanners []string, timeout time.Duration) *ExecutionManifest {
	m := NewExecutionManifest("SCAN MANIFEST")
	m.SetDescription("Security scanner configuration")
	m.AddTargetInfo(1, target)
	m.AddEmphasis("🔬", "Scanners", fmt.Sprintf("%d security modules", len(scanners)))
	m.AddWithIcon("📋", "Modules", strings.Join(scanners, ", "))
	m.AddWithIcon("⏰", "Timeout", timeout.String())
	return m
}

// DiscoveryManifest creates a manifest for discovery operations
func DiscoveryManifest(target string, depth int, phases []string) *ExecutionManifest {
	m := NewExecutionManifest("DISCOVERY MANIFEST")
	m.SetDescription("Reconnaissance configuration")
	m.AddTargetInfo(1, target)
	m.AddWithIcon("🔍", "Depth", fmt.Sprintf("%d levels", depth))
	m.AddEmphasis("📊", "Phases", fmt.Sprintf("%d phases", len(phases)))
	return m
}

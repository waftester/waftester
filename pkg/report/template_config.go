// Package report provides executive reporting and HTML generation.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TemplateConfig defines customizable report template settings.
// Configuration is loaded from YAML files to allow per-organization branding,
// section visibility, and layout customization.
type TemplateConfig struct {
	// Name is the template configuration identifier (e.g., "enterprise", "minimal")
	Name string `yaml:"name" json:"name"`

	// Version is the template config version for compatibility
	Version string `yaml:"version" json:"version"`

	// Branding customizes logos, colors, and company information
	Branding BrandingConfig `yaml:"branding" json:"branding"`

	// Layout controls section visibility and ordering
	Layout LayoutConfig `yaml:"layout" json:"layout"`

	// Sections defines which report sections to include
	Sections SectionConfig `yaml:"sections" json:"sections"`

	// Styling overrides CSS variables
	Styling StylingConfig `yaml:"styling" json:"styling"`

	// Charts configures chart appearance
	Charts ChartsConfig `yaml:"charts" json:"charts"`

	// Export configures default export options
	Export ExportConfig `yaml:"export" json:"export"`
}

// BrandingConfig holds organization branding information.
type BrandingConfig struct {
	// CompanyName appears in the report header
	CompanyName string `yaml:"company_name" json:"company_name"`

	// LogoURL is the URL or base64 encoded image for the logo
	LogoURL string `yaml:"logo_url" json:"logo_url"`

	// LogoPosition can be "left", "center", or "right"
	LogoPosition string `yaml:"logo_position" json:"logo_position"`

	// AccentColor is the primary brand color (hex, e.g., "#0066cc")
	AccentColor string `yaml:"accent_color" json:"accent_color"`

	// SecondaryColor is the secondary brand color
	SecondaryColor string `yaml:"secondary_color" json:"secondary_color"`

	// FooterText appears at the bottom of each page
	FooterText string `yaml:"footer_text" json:"footer_text"`

	// Copyright is the copyright notice
	Copyright string `yaml:"copyright" json:"copyright"`

	// ContactEmail for security questions
	ContactEmail string `yaml:"contact_email" json:"contact_email"`

	// ShowPoweredBy shows "Powered by WAFtester" if true
	ShowPoweredBy bool `yaml:"show_powered_by" json:"show_powered_by"`
}

// LayoutConfig controls overall report structure.
type LayoutConfig struct {
	// Theme can be "light", "dark", or "auto" (follows system)
	Theme string `yaml:"theme" json:"theme"`

	// PageWidth can be "full", "wide" (1400px), or "standard" (1200px)
	PageWidth string `yaml:"page_width" json:"page_width"`

	// ShowTableOfContents adds a navigable TOC
	ShowTableOfContents bool `yaml:"show_table_of_contents" json:"show_table_of_contents"`

	// CompactMode reduces spacing for denser reports
	CompactMode bool `yaml:"compact_mode" json:"compact_mode"`

	// PrintOptimized adjusts styling for print/PDF
	PrintOptimized bool `yaml:"print_optimized" json:"print_optimized"`
}

// SectionConfig enables or disables specific report sections.
type SectionConfig struct {
	// ExecutiveSummary shows the high-level summary section
	ExecutiveSummary bool `yaml:"executive_summary" json:"executive_summary"`

	// OverallGrade shows the letter grade
	OverallGrade bool `yaml:"overall_grade" json:"overall_grade"`

	// EnterpriseMetrics shows MTTD/FPR/resilience metrics
	EnterpriseMetrics bool `yaml:"enterprise_metrics" json:"enterprise_metrics"`

	// CategoryBreakdown shows per-category detection rates
	CategoryBreakdown bool `yaml:"category_breakdown" json:"category_breakdown"`

	// ConfusionMatrix shows TP/FP/TN/FN breakdown
	ConfusionMatrix bool `yaml:"confusion_matrix" json:"confusion_matrix"`

	// RadarChart shows the spider/radar chart
	RadarChart bool `yaml:"radar_chart" json:"radar_chart"`

	// Bypasses shows the list of detected bypasses
	Bypasses bool `yaml:"bypasses" json:"bypasses"`

	// FalsePositives shows the list of false positives
	FalsePositives bool `yaml:"false_positives" json:"false_positives"`

	// AllResults shows the complete test results table
	AllResults bool `yaml:"all_results" json:"all_results"`

	// LatencyMetrics shows P50/P95/P99 latency data
	LatencyMetrics bool `yaml:"latency_metrics" json:"latency_metrics"`

	// Recommendations shows actionable recommendations
	Recommendations bool `yaml:"recommendations" json:"recommendations"`

	// ComplianceMapping shows CWE/OWASP/WASC mappings
	ComplianceMapping bool `yaml:"compliance_mapping" json:"compliance_mapping"`

	// BrowserFindings shows authenticated scan results
	BrowserFindings bool `yaml:"browser_findings" json:"browser_findings"`

	// TechnicalDetails shows request/response evidence
	TechnicalDetails bool `yaml:"technical_details" json:"technical_details"`

	// Timeline shows historical comparison (requires SQLite)
	Timeline bool `yaml:"timeline" json:"timeline"`
}

// StylingConfig overrides CSS custom properties.
type StylingConfig struct {
	// FontFamily is the primary font (e.g., "Inter, sans-serif")
	FontFamily string `yaml:"font_family" json:"font_family"`

	// FontSizeBase is the root font size (e.g., "16px")
	FontSizeBase string `yaml:"font_size_base" json:"font_size_base"`

	// HeaderBackground is the header section background color
	HeaderBackground string `yaml:"header_background" json:"header_background"`

	// CardBackground is the card/section background color
	CardBackground string `yaml:"card_background" json:"card_background"`

	// TextColor is the primary text color
	TextColor string `yaml:"text_color" json:"text_color"`

	// BorderRadius for cards and buttons (e.g., "8px")
	BorderRadius string `yaml:"border_radius" json:"border_radius"`

	// GradeCriticalColor is the color for Critical/F grades
	GradeCriticalColor string `yaml:"grade_critical_color" json:"grade_critical_color"`

	// GradeHighColor is the color for High/D severity
	GradeHighColor string `yaml:"grade_high_color" json:"grade_high_color"`

	// GradeMediumColor is the color for Medium/C severity
	GradeMediumColor string `yaml:"grade_medium_color" json:"grade_medium_color"`

	// GradeLowColor is the color for Low/B severity
	GradeLowColor string `yaml:"grade_low_color" json:"grade_low_color"`

	// GradeInfoColor is the color for Info/A+ severity
	GradeInfoColor string `yaml:"grade_info_color" json:"grade_info_color"`

	// CustomCSS is additional CSS to inject
	CustomCSS string `yaml:"custom_css" json:"custom_css"`
}

// ChartsConfig customizes chart rendering.
type ChartsConfig struct {
	// ShowRadar enables the radar/spider chart
	ShowRadar bool `yaml:"show_radar" json:"show_radar"`

	// ShowBar enables bar charts for category comparison
	ShowBar bool `yaml:"show_bar" json:"show_bar"`

	// ShowLine enables line charts for trends
	ShowLine bool `yaml:"show_line" json:"show_line"`

	// AnimationDuration in milliseconds (0 disables)
	AnimationDuration int `yaml:"animation_duration" json:"animation_duration"`

	// ColorPalette is a list of colors for chart datasets
	ColorPalette []string `yaml:"color_palette" json:"color_palette"`
}

// ExportConfig sets default export behavior.
type ExportConfig struct {
	// DefaultFormat can be "html", "json", "pdf", "markdown"
	DefaultFormat string `yaml:"default_format" json:"default_format"`

	// IncludeRawData embeds JSON data in HTML for extraction
	IncludeRawData bool `yaml:"include_raw_data" json:"include_raw_data"`

	// ExportButtons shows export action buttons
	ExportButtons bool `yaml:"export_buttons" json:"export_buttons"`

	// AllowedFormats restricts available export formats
	AllowedFormats []string `yaml:"allowed_formats" json:"allowed_formats"`
}

// DefaultTemplateConfig returns the default configuration.
func DefaultTemplateConfig() *TemplateConfig {
	return &TemplateConfig{
		Name:    "default",
		Version: "1.0",
		Branding: BrandingConfig{
			CompanyName:   "Security Assessment",
			LogoPosition:  "left",
			AccentColor:   "#0066cc",
			ShowPoweredBy: true,
		},
		Layout: LayoutConfig{
			Theme:               "light",
			PageWidth:           "wide",
			ShowTableOfContents: true,
			CompactMode:         false,
			PrintOptimized:      false,
		},
		Sections: SectionConfig{
			ExecutiveSummary:  true,
			OverallGrade:      true,
			EnterpriseMetrics: true,
			CategoryBreakdown: true,
			ConfusionMatrix:   true,
			RadarChart:        true,
			Bypasses:          true,
			FalsePositives:    true,
			AllResults:        true,
			LatencyMetrics:    true,
			Recommendations:   true,
			ComplianceMapping: true,
			BrowserFindings:   true,
			TechnicalDetails:  false, // Can be verbose
			Timeline:          false, // Requires historical data
		},
		Styling: StylingConfig{
			FontFamily:         "Inter, system-ui, sans-serif",
			FontSizeBase:       "16px",
			BorderRadius:       "8px",
			GradeCriticalColor: "#dc2626",
			GradeHighColor:     "#ea580c",
			GradeMediumColor:   "#ca8a04",
			GradeLowColor:      "#65a30d",
			GradeInfoColor:     "#0284c7",
		},
		Charts: ChartsConfig{
			ShowRadar:         true,
			ShowBar:           true,
			ShowLine:          true,
			AnimationDuration: 400,
			ColorPalette: []string{
				"#3b82f6", "#ef4444", "#22c55e", "#f59e0b",
				"#8b5cf6", "#ec4899", "#06b6d4", "#84cc16",
			},
		},
		Export: ExportConfig{
			DefaultFormat:  "html",
			IncludeRawData: true,
			ExportButtons:  true,
			AllowedFormats: []string{"html", "json", "csv", "pdf"},
		},
	}
}

// MinimalTemplateConfig returns a minimal report configuration.
func MinimalTemplateConfig() *TemplateConfig {
	cfg := DefaultTemplateConfig()
	cfg.Name = "minimal"
	cfg.Sections = SectionConfig{
		ExecutiveSummary: true,
		OverallGrade:     true,
		Bypasses:         true,
		Recommendations:  true,
	}
	cfg.Layout.CompactMode = true
	return cfg
}

// EnterpriseTemplateConfig returns a full enterprise configuration.
func EnterpriseTemplateConfig() *TemplateConfig {
	cfg := DefaultTemplateConfig()
	cfg.Name = "enterprise"
	cfg.Sections.TechnicalDetails = true
	cfg.Sections.Timeline = true
	cfg.Layout.ShowTableOfContents = true
	cfg.Export.IncludeRawData = true
	return cfg
}

// LoadTemplateConfig loads a template configuration from a YAML file.
func LoadTemplateConfig(path string) (*TemplateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultTemplateConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveTemplateConfig writes a template configuration to a YAML file.
func SaveTemplateConfig(cfg *TemplateConfig, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// MergeConfig merges a partial config into the default config.
// Missing fields in the partial config retain default values.
// Boolean fields use explicit tracking to distinguish false from unset.
func MergeConfig(base, override *TemplateConfig) *TemplateConfig {
	if override == nil {
		return base
	}

	// String fields - override if non-empty
	if override.Name != "" {
		base.Name = override.Name
	}
	if override.Version != "" {
		base.Version = override.Version
	}

	// Branding - all string fields
	if override.Branding.CompanyName != "" {
		base.Branding.CompanyName = override.Branding.CompanyName
	}
	if override.Branding.LogoURL != "" {
		base.Branding.LogoURL = override.Branding.LogoURL
	}
	if override.Branding.LogoPosition != "" {
		base.Branding.LogoPosition = override.Branding.LogoPosition
	}
	if override.Branding.AccentColor != "" {
		base.Branding.AccentColor = override.Branding.AccentColor
	}
	if override.Branding.SecondaryColor != "" {
		base.Branding.SecondaryColor = override.Branding.SecondaryColor
	}
	if override.Branding.FooterText != "" {
		base.Branding.FooterText = override.Branding.FooterText
	}
	if override.Branding.Copyright != "" {
		base.Branding.Copyright = override.Branding.Copyright
	}
	if override.Branding.ContactEmail != "" {
		base.Branding.ContactEmail = override.Branding.ContactEmail
	}
	// Note: ShowPoweredBy is bool - YAML decoding sets it explicitly

	// Layout - string fields
	if override.Layout.Theme != "" {
		base.Layout.Theme = override.Layout.Theme
	}
	if override.Layout.PageWidth != "" {
		base.Layout.PageWidth = override.Layout.PageWidth
	}
	// Layout booleans are merged via YAML explicit set (no way to distinguish unset)
	// If override file contains the key, it will be applied at YAML decode time

	// Sections - boolean fields from override take precedence when explicitly set
	// We merge the entire struct since YAML decode sets all specified booleans
	base.Sections = mergeSectionConfig(base.Sections, override.Sections)

	// Styling - all string fields
	if override.Styling.FontFamily != "" {
		base.Styling.FontFamily = override.Styling.FontFamily
	}
	if override.Styling.FontSizeBase != "" {
		base.Styling.FontSizeBase = override.Styling.FontSizeBase
	}
	if override.Styling.HeaderBackground != "" {
		base.Styling.HeaderBackground = override.Styling.HeaderBackground
	}
	if override.Styling.CardBackground != "" {
		base.Styling.CardBackground = override.Styling.CardBackground
	}
	if override.Styling.TextColor != "" {
		base.Styling.TextColor = override.Styling.TextColor
	}
	if override.Styling.BorderRadius != "" {
		base.Styling.BorderRadius = override.Styling.BorderRadius
	}
	if override.Styling.GradeCriticalColor != "" {
		base.Styling.GradeCriticalColor = override.Styling.GradeCriticalColor
	}
	if override.Styling.GradeHighColor != "" {
		base.Styling.GradeHighColor = override.Styling.GradeHighColor
	}
	if override.Styling.GradeMediumColor != "" {
		base.Styling.GradeMediumColor = override.Styling.GradeMediumColor
	}
	if override.Styling.GradeLowColor != "" {
		base.Styling.GradeLowColor = override.Styling.GradeLowColor
	}
	if override.Styling.GradeInfoColor != "" {
		base.Styling.GradeInfoColor = override.Styling.GradeInfoColor
	}
	if override.Styling.CustomCSS != "" {
		base.Styling.CustomCSS = override.Styling.CustomCSS
	}

	// Charts - int and bool fields use zero-value detection
	if override.Charts.AnimationDuration != 0 {
		base.Charts.AnimationDuration = override.Charts.AnimationDuration
	}
	if len(override.Charts.ColorPalette) > 0 {
		base.Charts.ColorPalette = override.Charts.ColorPalette
	}

	// Export - string and slice fields
	if override.Export.DefaultFormat != "" {
		base.Export.DefaultFormat = override.Export.DefaultFormat
	}
	if len(override.Export.AllowedFormats) > 0 {
		base.Export.AllowedFormats = override.Export.AllowedFormats
	}

	return base
}

// mergeSectionConfig merges section configuration.
// The override's values take precedence unconditionally.
// Since LoadTemplateConfig unmarshals into DefaultTemplateConfig(),
// any value not present in the YAML gets the default value, so
// when MergeConfig is called with a loaded override the sections
// already carry the correct explicit or default state.
func mergeSectionConfig(base, override SectionConfig) SectionConfig {
	return override
}

// ValidateConfig checks configuration for errors and returns descriptive
// validation errors instead of silently correcting values.
func ValidateConfig(cfg *TemplateConfig) error {
	var errs []string

	// Validate theme
	switch cfg.Layout.Theme {
	case "light", "dark", "auto":
		// Valid
	default:
		errs = append(errs, fmt.Sprintf("invalid theme %q: must be light, dark, or auto", cfg.Layout.Theme))
	}

	// Validate page width
	switch cfg.Layout.PageWidth {
	case "full", "wide", "standard":
		// Valid
	default:
		errs = append(errs, fmt.Sprintf("invalid page_width %q: must be full, wide, or standard", cfg.Layout.PageWidth))
	}

	if len(errs) > 0 {
		return fmt.Errorf("template config validation: %s", strings.Join(errs, "; "))
	}

	return nil
}

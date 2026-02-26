package main

import "flag"

// SmartModeFlags holds WAF-aware smart testing flags shared by scan,
// autoscan, and bypass commands.
type SmartModeFlags struct {
	Enabled *bool
	Mode    *string
	Verbose *bool
}

// Register binds smart mode flags to the given FlagSet with standard defaults.
func (sf *SmartModeFlags) Register(fs *flag.FlagSet) {
	sf.Enabled = fs.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	sf.Mode = fs.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	sf.Verbose = fs.Bool("smart-verbose", false, "Show detailed WAF detection info")
}

// RegisterBypass binds smart mode flags with bypass-specific defaults.
func (sf *SmartModeFlags) RegisterBypass(fs *flag.FlagSet) {
	sf.Enabled = fs.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	sf.Mode = fs.String("smart-mode", "bypass", "Smart mode type: quick, standard, full, bypass, stealth")
	sf.Verbose = fs.Bool("smart-verbose", false, "Show detailed WAF detection info")
}

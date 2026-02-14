package apispec

import (
	"flag"
	"strings"
)

// SpecFlags registers spec-related flags on a FlagSet. Shared between
// scan and auto commands so flags stay consistent.
type SpecFlags struct {
	SpecPath   *string
	SpecURL    *string
	Group      *string
	SkipGroup  *string
	PathFilter *string
	Var        *varSlice
	EnvFile    *string
	DryRun     *bool
	Confirm    *bool
	Intensity  *string
}

// Register adds spec flags to the given FlagSet.
func (sf *SpecFlags) Register(fs *flag.FlagSet) {
	sf.SpecPath = fs.String("spec", "", "API spec file (OpenAPI 3.x, Swagger 2.0, Postman, HAR)")
	sf.SpecURL = fs.String("spec-url", "", "API spec URL (fetched at scan time)")
	sf.Group = fs.String("group", "", "Scan only endpoints in this group/tag (comma-separated)")
	sf.SkipGroup = fs.String("skip-group", "", "Exclude endpoints in this group/tag (comma-separated)")
	sf.PathFilter = fs.String("path", "", "Filter endpoints by path glob (e.g., /users/*)")
	sf.Var = &varSlice{}
	fs.Var(sf.Var, "var", "Variable override key=value (repeatable)")
	sf.EnvFile = fs.String("env", "", "Postman environment file (.postman_environment.json)")
	sf.DryRun = fs.Bool("spec-dry-run", false, "Show spec scan plan without executing")
	sf.Confirm = fs.Bool("yes", false, "Skip confirmation prompt for spec scans")
	fs.BoolVar(sf.Confirm, "y", false, "Skip confirmation (alias)")
	sf.Intensity = fs.String("intensity", "normal", "Spec scan intensity: quick, normal, deep, paranoid")
}

// ToConfig converts parsed flag values into a SpecConfig.
func (sf *SpecFlags) ToConfig() *SpecConfig {
	cfg := &SpecConfig{}

	if sf.SpecPath != nil {
		cfg.SpecPath = *sf.SpecPath
	}
	if sf.SpecURL != nil {
		cfg.SpecURL = *sf.SpecURL
	}
	if sf.Group != nil && *sf.Group != "" {
		cfg.Groups = splitCSV(*sf.Group)
	}
	if sf.SkipGroup != nil && *sf.SkipGroup != "" {
		cfg.SkipGroups = splitCSV(*sf.SkipGroup)
	}
	if sf.PathFilter != nil {
		cfg.PathFilter = *sf.PathFilter
	}
	if sf.Var != nil {
		cfg.Variables = sf.Var.ToMap()
	}
	if sf.EnvFile != nil {
		cfg.EnvFile = *sf.EnvFile
	}
	if sf.DryRun != nil {
		cfg.DryRun = *sf.DryRun
	}
	if sf.Confirm != nil {
		cfg.Confirm = *sf.Confirm
	}
	if sf.Intensity != nil {
		cfg.Intensity = Intensity(*sf.Intensity)
	}

	return cfg
}

// varSlice implements flag.Value for repeatable --var key=value flags.
type varSlice []string

func (v *varSlice) String() string {
	if v == nil {
		return ""
	}
	return strings.Join(*v, ", ")
}

func (v *varSlice) Set(s string) error {
	*v = append(*v, s)
	return nil
}

// ToMap converts the key=value pairs into a map.
func (v *varSlice) ToMap() map[string]string {
	m := make(map[string]string)
	for _, pair := range *v {
		k, val, ok := strings.Cut(pair, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	return m
}

// splitCSV splits a comma-separated string into trimmed, non-empty parts.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

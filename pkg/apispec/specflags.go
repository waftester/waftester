package apispec

import (
	"flag"
	"fmt"
	"os"
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
		switch Intensity(*sf.Intensity) {
		case IntensityQuick, IntensityNormal, IntensityDeep, IntensityParanoid:
			cfg.Intensity = Intensity(*sf.Intensity)
		default:
			fmt.Fprintf(os.Stderr, "warning: unknown intensity %q, using %q\n", *sf.Intensity, IntensityNormal)
			cfg.Intensity = IntensityNormal
		}
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

// RejectSpecFlags checks os.Args for --spec or --spec-url flags and exits
// with a clear error if found. Call from commands that do not support spec
// scanning (bypass, assess, fuzz, etc.).
func RejectSpecFlags(command string) {
	if err := CheckSpecFlagsRejected(command, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// CheckSpecFlagsRejected returns an error if args contain --spec or --spec-url.
// Extracted for testability.
func CheckSpecFlagsRejected(command string, args []string) error {
	for _, arg := range args {
		if arg == "--spec" || strings.HasPrefix(arg, "--spec=") ||
			arg == "--spec-url" || strings.HasPrefix(arg, "--spec-url=") {
			return fmt.Errorf(
				"Error: the %q command does not support --spec or --spec-url flags.\n"+
					"Use \"waftester scan --spec <file>\" or \"waftester auto --spec <file>\" instead.",
				command,
			)
		}
	}
	return nil
}

// pkg/input/flags.go
package input

import "strings"

// StringSliceFlag implements flag.Value for repeated/comma-separated string flags
type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSliceFlag) Set(value string) error {
	// Split by comma and append each value
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			*s = append(*s, v)
		}
	}
	return nil
}

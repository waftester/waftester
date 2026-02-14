package apispec

import (
	"testing"
)

func TestCheckSpecFlagsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
		wantErr bool
	}{
		{
			name:    "no spec flags",
			command: "bypass",
			args:    []string{"-u", "https://example.com", "--scan-type", "sqli"},
			wantErr: false,
		},
		{
			name:    "spec flag bare",
			command: "bypass",
			args:    []string{"-u", "https://example.com", "--spec", "api.yaml"},
			wantErr: true,
		},
		{
			name:    "spec flag with equals",
			command: "fuzz",
			args:    []string{"--spec=api.yaml"},
			wantErr: true,
		},
		{
			name:    "spec-url flag bare",
			command: "assess",
			args:    []string{"--spec-url", "https://example.com/api.yaml"},
			wantErr: true,
		},
		{
			name:    "spec-url flag with equals",
			command: "race",
			args:    []string{"--spec-url=https://example.com/api.yaml"},
			wantErr: true,
		},
		{
			name:    "empty args",
			command: "bypass",
			args:    nil,
			wantErr: false,
		},
		{
			name:    "similar but not spec flag",
			command: "bypass",
			args:    []string{"--special", "value"},
			wantErr: false,
		},
		{
			name:    "error message includes command name",
			command: "headless",
			args:    []string{"--spec", "api.yaml"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := CheckSpecFlagsRejected(tt.command, tt.args)

			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil {
				errStr := err.Error()
				if !contains(errStr, tt.command) {
					t.Errorf("error should mention command %q, got: %s", tt.command, errStr)
				}
				if !contains(errStr, "scan --spec") {
					t.Errorf("error should suggest scan --spec, got: %s", errStr)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

package main

import (
	"flag"
	"testing"
)

func TestSmartModeFlagsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var sf SmartModeFlags
	sf.Register(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *sf.Enabled {
		t.Error("expected Enabled=false by default")
	}
	if *sf.Mode != "standard" {
		t.Errorf("expected Mode=standard, got %q", *sf.Mode)
	}
	if *sf.Verbose {
		t.Error("expected Verbose=false by default")
	}
}

func TestSmartModeFlagsRegister(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var sf SmartModeFlags
	sf.Register(fs)
	if err := fs.Parse([]string{"-smart", "-smart-mode", "full", "-smart-verbose"}); err != nil {
		t.Fatal(err)
	}
	if !*sf.Enabled {
		t.Error("expected Enabled=true")
	}
	if *sf.Mode != "full" {
		t.Errorf("expected Mode=full, got %q", *sf.Mode)
	}
	if !*sf.Verbose {
		t.Error("expected Verbose=true")
	}
}

func TestSmartModeFlagsBypassDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var sf SmartModeFlags
	sf.RegisterBypass(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *sf.Mode != "bypass" {
		t.Errorf("expected Mode=bypass for RegisterBypass, got %q", *sf.Mode)
	}
}

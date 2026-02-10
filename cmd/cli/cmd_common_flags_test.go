package main

import (
	"flag"
	"testing"
)

func TestCommonFlagsRegister(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cf CommonFlags
	cf.Register(fs, 30)

	// Parse simulated flags
	err := fs.Parse([]string{
		"-u", "https://example.com",
		"-timeout", "60",
		"-skip-verify",
		"-verbose",
	})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cf.Targets) != 1 || cf.Targets[0] != "https://example.com" {
		t.Errorf("Targets = %v, want [https://example.com]", cf.Targets)
	}
	if cf.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", cf.Timeout)
	}
	if !cf.SkipVerify {
		t.Error("SkipVerify = false, want true")
	}
	if !cf.Verbose {
		t.Error("Verbose = false, want true")
	}
}

func TestCommonFlagsRegisterDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cf CommonFlags
	cf.Register(fs, 10)

	_ = fs.Parse([]string{})

	if cf.Timeout != 10 {
		t.Errorf("Timeout default = %d, want 10", cf.Timeout)
	}
	if cf.SkipVerify {
		t.Error("SkipVerify default should be false")
	}
	if cf.Verbose {
		t.Error("Verbose default should be false")
	}
	if cf.ListFile != "" {
		t.Errorf("ListFile default = %q, want empty", cf.ListFile)
	}
}

func TestCommonFlagsMultipleTargets(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cf CommonFlags
	cf.Register(fs, 30)

	err := fs.Parse([]string{
		"-u", "https://a.com",
		"-u", "https://b.com",
		"-target", "https://c.com",
	})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cf.Targets) != 3 {
		t.Errorf("Targets length = %d, want 3", len(cf.Targets))
	}
}

func TestCommonFlagsTargetSource(t *testing.T) {
	var cf CommonFlags
	cf.Targets = []string{"https://example.com"}
	cf.ListFile = "targets.txt"
	cf.StdinInput = true

	ts := cf.TargetSource()

	if len(ts.URLs) != 1 || ts.URLs[0] != "https://example.com" {
		t.Errorf("TargetSource.URLs = %v, want [https://example.com]", ts.URLs)
	}
	if ts.ListFile != "targets.txt" {
		t.Errorf("TargetSource.ListFile = %q, want targets.txt", ts.ListFile)
	}
	if !ts.Stdin {
		t.Error("TargetSource.Stdin = false, want true")
	}
}

func TestCommonFlagsListFileAndStdin(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var cf CommonFlags
	cf.Register(fs, 30)

	err := fs.Parse([]string{"-l", "hosts.txt", "-stdin"})
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if cf.ListFile != "hosts.txt" {
		t.Errorf("ListFile = %q, want hosts.txt", cf.ListFile)
	}
	if !cf.StdinInput {
		t.Error("StdinInput = false, want true")
	}
}

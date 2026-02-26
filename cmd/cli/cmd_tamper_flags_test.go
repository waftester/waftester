package main

import (
	"flag"
	"testing"
)

func TestTamperFlagsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var tf TamperFlags
	tf.Register(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *tf.List != "" {
		t.Errorf("expected List empty, got %q", *tf.List)
	}
	if *tf.Auto {
		t.Error("expected Auto=false by default")
	}
	if *tf.Profile != "standard" {
		t.Errorf("expected Profile=standard, got %q", *tf.Profile)
	}
	if *tf.Dir != "" {
		t.Errorf("expected Dir empty, got %q", *tf.Dir)
	}
}

func TestTamperFlagsRegister(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var tf TamperFlags
	tf.Register(fs)
	if err := fs.Parse([]string{"-tamper", "randomcase,space2comment", "-tamper-auto", "-tamper-profile", "aggressive", "-tamper-dir", "/tmp/tampers"}); err != nil {
		t.Fatal(err)
	}
	if *tf.List != "randomcase,space2comment" {
		t.Errorf("expected List=randomcase,space2comment, got %q", *tf.List)
	}
	if !*tf.Auto {
		t.Error("expected Auto=true")
	}
	if *tf.Profile != "aggressive" {
		t.Errorf("expected Profile=aggressive, got %q", *tf.Profile)
	}
	if *tf.Dir != "/tmp/tampers" {
		t.Errorf("expected Dir=/tmp/tampers, got %q", *tf.Dir)
	}
}

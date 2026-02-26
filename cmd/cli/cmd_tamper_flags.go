package main

import "flag"

// TamperFlags holds WAF bypass tamper script flags shared by scan and autoscan.
type TamperFlags struct {
	List    *string
	Auto    *bool
	Profile *string
	Dir     *string
}

// Register binds tamper flags to the given FlagSet.
func (tf *TamperFlags) Register(fs *flag.FlagSet) {
	tf.List = fs.String("tamper", "", "Comma-separated tamper scripts: space2comment,randomcase,charencode")
	tf.Auto = fs.Bool("tamper-auto", false, "Auto-select tampers based on detected WAF")
	tf.Profile = fs.String("tamper-profile", "standard", "Tamper profile: stealth, standard, aggressive, bypass")
	tf.Dir = fs.String("tamper-dir", "", "Directory of .tengo script tampers to load")
}

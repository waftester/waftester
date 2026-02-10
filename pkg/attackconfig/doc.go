// Package attackconfig provides shared configuration types
// for all WAFtester attack and testing packages.
//
// Attack packages embed [Base] to inherit common fields like
// Timeout, UserAgent, Client, MaxPayloads, and Concurrency:
//
//	type SQLiConfig struct {
//	    attackconfig.Base
//	    DBMS          string
//	    TimeThreshold time.Duration
//	}
package attackconfig

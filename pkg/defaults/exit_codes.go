package defaults

// Exit codes for the CLI.
const (
	ExitSuccess       = 0 // Clean exit, no issues found
	ExitBypassFound   = 1 // WAF bypass detected
	ExitUserError     = 2 // Invalid arguments or configuration
	ExitNetworkError  = 3 // Network/connection failure
	ExitInternalError = 4 // Unexpected internal error
)

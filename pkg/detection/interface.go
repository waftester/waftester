package detection

// HostChecker is the consumer-side interface for host health checking.
// Consumers that need to check whether a host should be skipped (due to
// connection drops, bans, or rate limiting) should depend on this interface.
type HostChecker interface {
	ShouldSkipHost(host string) (skip bool, reason string)
	RecordDrop(host string)
	RecordBan(host string)
}

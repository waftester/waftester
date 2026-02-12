package hooks

import "log/slog"

// orDefault returns l if non-nil, otherwise slog.Default().
func orDefault(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

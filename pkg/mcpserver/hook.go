package mcpserver

import (
	"context"

	"github.com/waftester/waftester/pkg/output/events"
)

// Hook bridges WAFtester's event dispatcher to the MCP server,
// allowing real-time scan progress and result streaming.
// It implements the dispatcher.Hook interface.
type Hook struct {
	onEvent func(events.Event)
}

// NewHook creates a Hook that calls fn for every event.
// Typically used to forward events as MCP log notifications.
func NewHook(fn func(events.Event)) *Hook {
	return &Hook{onEvent: fn}
}

// OnEvent is called by the dispatcher for each matching event.
func (h *Hook) OnEvent(_ context.Context, event events.Event) error {
	if h.onEvent != nil {
		h.onEvent(event)
	}
	return nil
}

// EventTypes returns nil to receive all event types.
func (h *Hook) EventTypes() []events.EventType {
	return nil // receive everything
}

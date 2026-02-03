package events

// ErrorEvent is emitted when an error occurs during scanning.
// It can represent both recoverable and fatal errors.
type ErrorEvent struct {
	BaseEvent
	Target    string `json:"target,omitempty"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
	Fatal     bool   `json:"fatal"`
}

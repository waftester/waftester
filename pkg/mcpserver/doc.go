// Package mcpserver exposes waf-tester as a Model Context Protocol (MCP) server,
// enabling AI assistants (Claude, VS Code Copilot, Cursor, etc.) to drive
// comprehensive WAF security testing through natural conversation.
//
// # Architecture
//
// The server is built on the official MCP Go SDK and exposes three categories
// of capabilities:
//
//   - Tools:     Actionable operations (scan, discover, detect_waf, assess, …)
//   - Resources: Domain knowledge the AI can read (signatures, techniques, config)
//   - Prompts:   Pre-built workflow templates for common security tasks
//
// # Tool Design Principles
//
// Every tool follows enterprise MCP best practices:
//
//   - Detailed markdown descriptions with usage guidance and examples
//   - Complete JSON schemas with enums, defaults, min/max bounds
//   - Proper annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
//   - Composable: output of one tool feeds naturally into another
//   - Actionable errors that suggest the correct next step
//   - Rich progress streaming during long operations
//
// # Transports
//
// Two transport modes are supported:
//
//   - stdio:  Communicates over stdin/stdout (default). Used by IDE integrations.
//   - HTTP:   Streamable HTTP with SSE. Used for remote/Docker deployments.
//
// # Usage
//
//	cfg := &mcpserver.Config{PayloadDir: "./payloads"}
//	srv := mcpserver.New(cfg)
//	err := srv.RunStdio(ctx)
package mcpserver

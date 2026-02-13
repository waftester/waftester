# AGENTS.md

WAFtester is a Go CLI for WAF security testing. Module: `github.com/waftester/waftester`.

## Agent Coordination

When multiple agents work on this repository:

- Each agent owns specific files during a task. Don't edit files another agent is working on.
- If you are one of several agents, include this awareness in your planning.
- Define clear success criteria before starting work.
- Use conventional commits so other agents can understand what changed and why.

All coding standards, testing, security, and workflow rules are in `.github/instructions/`.

## Build & Test

```bash
go build ./...                  # Compile
go test -v -race ./...          # Test (always -race)
golangci-lint run               # Lint
./waftester scan https://ex.com # Run
```

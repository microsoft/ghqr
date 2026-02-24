---
applyTo: "**/*.go"
---

# Go Coding Instructions for ghqr

## Project Context

This is **GitHub Quick Review (ghqr)** — a Go CLI tool (`github.com/microsoft/ghqr`) that scans GitHub enterprises, organizations, and repositories for best practice compliance and security posture.

## Code Style

- Use **camelCase** for all variable names
- Use **MixedCaps** for exported identifiers
- Add **godoc-style comments** to every exported function, type, and constant
- Keep functions small and focused on a single responsibility
- Prefer **explicit over implicit** — avoid magic values

## Error Handling

```go
// Always wrap errors with context
result, err := doSomething()
if err != nil {
    return fmt.Errorf("context about what failed: %w", err)
}
```

- Check errors immediately after the call
- Use lowercase error messages without trailing punctuation
- Use `errors.Is` / `errors.As` for sentinel error checks

## Best Practice Evaluators

When writing evaluators in `internal/scanners/bestpractices/`:

```go
// Always guard against nil input
func (e *Evaluator) EvaluateX(data *scanners.XData) *EvaluationResult {
    if data == nil {
        return noDataResult("X data unavailable")
    }
    var issues, recommendations []Issue
    // use addIssue(...) and addRecommendation(...)
    return createResult(e, issues, recommendations)
}
```

- Use `SeverityCritical / SeverityHigh / SeverityMedium / SeverityLow / SeverityInfo` constants
- Use `Category*` constants from `types.go`
- Use `addIssue` for active problems, `addRecommendation` for proactive suggestions

## GitHub API Usage

- Use `github.com/shurcooL/githubv4` for GraphQL queries
- Use `github.com/google/go-github` for REST API calls
- Always handle pagination for list operations
- Respect rate limits; use exponential backoff for retries

## Logging

Use `github.com/rs/zerolog/log` for structured logging:

```go
log.Info().Str("org", orgName).Msg("scanning organization")
log.Error().Err(err).Str("repo", repoName).Msg("failed to scan")
```

- Never use `fmt.Println` for operational output; use the logger
- Gate verbose output behind `log.Debug()` (enabled via `--debug` flag)

## Testing

- Write **table-driven tests** for evaluators and utility functions
- Test both the "issue found" and "no issue" paths
- Use interfaces to enable mocking of GitHub API clients
- Run `make test` before every commit — this is mandatory

## MCP Server

When adding MCP tools in `internal/mcpserver/`:
- Register tools in `tools.go`
- Implement handlers in `tool_scan.go`
- Use descriptive tool names and clear parameter descriptions for AI discoverability

## Forbidden Patterns

- Do **not** use `log.Fatal` outside of `main` or command entry points
- Do **not** hardcode severity or category strings — always use constants
- Do **not** ignore errors with `_` unless it is genuinely safe and well-commented
- Do **not** use `init()` functions outside of `cmd/` packages

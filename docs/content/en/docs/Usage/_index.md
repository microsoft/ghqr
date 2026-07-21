---
title: Usage
description: Use GitHub Quick Review to analyze GitHub enterprises, organizations, and repositories.
weight: 3
---

## Authentication

**GitHub Quick Review (ghqr)** resolves credentials via a chain, similar to Azure's `DefaultAzureCredential`:

1. `GH_TOKEN` environment variable
2. `GITHUB_TOKEN` environment variable
3. **`gh` CLI config** — run `gh auth login` once; ghqr picks it up automatically
4. System keyring (macOS Keychain, Linux Secret Service)

For GHES instances, run `gh auth login --hostname <ghes-host>` or set `GH_TOKEN`. Note: `GITHUB_TOKEN` is scoped to github.com/ghe.com only (see CVE-2024-53859) — for GHES it is accepted as a backward-compat fallback only.

### Required Token Scopes for GitHub.com

| Scope | Purpose |
|-------|---------|
| `read:org` | Read organization settings and members |
| `read:enterprise` | Read enterprise settings |
| `repo` | Read repository settings, branch protection, and security features |
| `read:audit_log` | Read audit log configuration |
| `read:user` | Read user information |
| `copilot` | Read Copilot seat and policy information |

### Required Token Scopes for GHES

Create a Personal Access Token on your GHES instance with these scopes:

| Scope | Purpose |
|-------|---------|
| `site_admin` | Read server settings, license, admin stats, and audit log |
| `read:org` | Read organization settings and members |
| `repo` | Read repository settings and security features |
| `read:audit_log` | Read audit log events |

> **Note:** For GHES, ghqr resolves the token via: `GH_TOKEN` env var → `gh` CLI config (run `gh auth login --hostname <host>`) → system keyring → `GITHUB_TOKEN` (backward-compat fallback). Tokens without `site_admin` produce a degraded scan: license, admin stats, audit log, and management settings are reported as unavailable rather than treated as misconfigured.

## GitHub Enterprise Cloud with Data Residency (GHE.com)

If your organization uses [GitHub Enterprise Cloud with data residency](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/about-github-enterprise-cloud-with-data-residency), your API endpoints are on a custom `ghe.com` subdomain instead of `github.com`.

Specify your hostname using either:

- The `--hostname` / `-H` flag:

  ```bash
  ghqr scan -o my-org -H mycompany.ghe.com
  ```

- The `GH_HOST` environment variable:

  ```bash
  export GH_HOST=mycompany.ghe.com
  ghqr scan -o my-org
  ```

## Running Scans

### Scan a Single Organization

```bash
# Option A: authenticate with gh CLI (no env var needed)
gh auth login
ghqr scan -o my-org

# Option B: set token manually
export GITHUB_TOKEN=<your-personal-access-token>
ghqr scan -o my-org
```

### Scan a GitHub Enterprise

```bash
ghqr scan -e my-enterprise
```

### Scan a GitHub Enterprise Server Instance

```bash
# Option A: authenticate with gh CLI (recommended)
gh auth login --hostname ghes.example.com
ghqr scan --ghes ghes.example.com

# Option B: set token manually
export GH_TOKEN=<your-ghes-personal-access-token>
ghqr scan --ghes ghes.example.com
```

### Scan Multiple GHES Instances

```bash
ghqr scan --ghes ghes1.example.com --ghes ghes2.example.com
```

### Combine GitHub.com Enterprise and GHES Scans

```bash
ghqr scan -e my-enterprise --ghes ghes.example.com
```

### Specify a Custom Output Name

```bash
ghqr scan -o my-org -n my-org-audit-2026
```

## GitHub Enterprise Server (GHES) Scan Details

**GitHub Quick Review** supports scanning on-premise GitHub Enterprise Server instances to assess security posture, configuration best practices, and compliance.

### What GHES Scan Checks

| Category | Checks |
|----------|--------|
| **Server Version** | Installed version detection, supported release verification |
| **Authentication** | Auth mode (built-in/SAML/LDAP/CAS), open signup, password auth |
| **Networking** | Subdomain isolation (critical), private mode, TLS enforcement |
| **License** | Seat utilization, expiration warnings (30/90 days) |
| **Advanced Security** | GHAS enablement, secret scanning, push protection, code scanning |
| **Dependencies** | Dependabot alerts and security updates enablement |
| **Actions** | GitHub Actions enablement, self-hosted runner security guidance |
| **Audit Log** | Suspicious event detection, log forwarding recommendations |
| **Infrastructure** | Site admin count, backup-utils verification, HA replica checks |
| **Admin Stats** | User/org/repo counts, suspended user ratio, disabled orgs |

### GHES-Specific Suspicious Audit Events

The GHES audit log scanner detects these additional server-specific events:

- `staff.fake_login` - Admin impersonation of another user
- `staff.unlock` - Admin unlock of a user account
- `staff.set_site_admin` - Admin privilege escalation
- `user.suspend` / `user.unsuspend` - User account state changes

These are in addition to the standard events (`repo.destroy`, `org.remove_member`, etc.).

### Manual Verification Items

Some GHES configuration items cannot be verified automatically via the API. The scan report flags these for manual review:

- **Audit log forwarding (syslog)** - Verify in Site Admin > Monitoring > Log forwarding
- **Backup configuration** - Verify GitHub Enterprise Server Backup Utilities (backup-utils) are configured and tested
- **High Availability (HA)** - Verify replica configuration if HA is required for your deployment

## Output Formats

**GitHub Quick Review (ghqr)** supports three output formats: `xlsx` (default), `markdown`, and `json`.

### xlsx (Default)

The default output format produces an Excel workbook with multiple sheets covering all findings, organization summaries, and repository details.

```bash
ghqr scan -o my-org
```

### markdown

Generate a Markdown report suitable for wikis, pull request descriptions, or archiving alongside code:

```bash
ghqr scan -o my-org --markdown
```

### json

Generate a machine-readable JSON report for integration with other tools or pipelines:

```bash
ghqr scan -o my-org --json
```

### Changing the Output File Name

Use the `-n` flag to set a custom output file name:

```bash
# Linux / macOS
timestamp=$(date '+%Y%m%d%H%M%S')
ghqr scan -o my-org -n "ghqr_report_$timestamp"

# Windows PowerShell
$timestamp = Get-Date -Format 'yyyyMMddHHmmss'
.\ghqr scan -o my-org -n "ghqr_report_$timestamp"
```

## Replaying a Previous Scan

To re-evaluate rules or re-render reports without re-querying the GitHub API, replay an existing scan JSON file:

```bash
ghqr scan --from-json ghqr_20260417_143426.json
```

The scan stages are skipped, and a fresh output file is produced. No GitHub API calls or token are required.

> **Note:** The JSON renderer compacts `collaborators` and `deploy_keys` arrays into summaries, so per-collaborator and per-deploy-key rules cannot be re-evaluated from a replayed file.

## Generating Synthetic (Mock) Scans

For demos, report-template development, or testing the renderers without a GitHub token, generate a synthetic scan:

```bash
# 1 org with 5 repos (defaults)
ghqr mock

# 3 orgs, 10 repos each, wrapped in an enterprise
ghqr mock -o 3 -r 10 -e mock-ent --seed 42

# Generate JSON and immediately render markdown and xlsx
ghqr mock -o 5 -r 20 --profile noisy --render
```

### Mock Command Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --orgs` | `1` | Number of organizations to synthesize |
| `-r, --repos` | `5` | Number of repositories per organization |
| `-e, --enterprise` | _(none)_ | Optional enterprise slug wrapping all orgs |
| `--profile` | `typical` | Distribution profile: `clean`, `typical`, or `noisy` |
| `--seed` | `0` | RNG seed for reproducible output (`0` = time-based) |
| `-O, --output` | `ghqr_mock_<timestamp>.json` | Output JSON path |
| `--render` | `false` | After writing JSON, replay it through the scan pipeline to produce md/xlsx |

## MCP Server (Model Context Protocol)

**GitHub Quick Review** includes a Model Context Protocol (MCP) server that enables AI assistants and tools to interact with ghqr functionality. The MCP server can run in two modes.

### stdio Mode (Default)

The stdio mode is designed for integration with tools like VS Code and AI assistants that communicate via standard input/output:

```bash
ghqr mcp
```

### HTTP/SSE Mode

The HTTP/SSE mode allows the MCP server to be accessed over HTTP, enabling remote access and web-based integrations:

```bash
# Start on default port (:8080)
ghqr mcp --mode http

# Start on a custom port
ghqr mcp --mode http --addr :3000

# Start with a specific host and port
ghqr mcp --mode http --addr localhost:9090
```

### Configuring with VS Code / GitHub Copilot

Add to your `.vscode/mcp.json`:

```json
{
  "servers": {
    "ghqr": {
      "type": "stdio",
      "command": "ghqr",
      "args": ["mcp"],
      "env": {
        "GITHUB_TOKEN": "${input:githubToken}"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan` | Scan GitHub enterprises, organizations, or repositories for best practices and security recommendations |

The `scan` tool accepts these optional array arguments:

- `enterprises` - Enterprise slugs to scan
- `organizations` - Organization slugs to scan
- `repositories` - Repository full names in `owner/repo` format
- `ghes_instances` - GHES hostnames (for example `ghes.example.com`)

> When using `ghes_instances`, ensure `GH_TOKEN` or `GITHUB_TOKEN` is valid for all specified instances.

## Listing All Recommendations

You can list all available recommendations in the built-in registry:

```bash
# List as a formatted table
ghqr list-recommendations

# Filter by scope
ghqr list-recommendations --scope repository

# Filter by severity
ghqr list-recommendations --severity critical

# Filter by category
ghqr list-recommendations --category branch_protection

# Output as JSON
ghqr list-recommendations --json

# Output as a Markdown table
ghqr list-recommendations --markdown
```

## Debugging

Use the `--debug` flag to enable verbose logging for any command:

```bash
ghqr scan -o my-org --debug
```

## Help

Get help for any command by running:

```bash
ghqr --help
ghqr scan --help
ghqr mcp --help
ghqr mock --help
```

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func RegisterTools(s *server.MCPServer) {
	// Main scan tool
	scan := mcp.NewTool("scan",
		mcp.WithDescription(
			`Run a GitHub Quick Review (ghqr) scan to analyze GitHub resources and identify recommendations for improvement.

WHAT GETS SCANNED:
- Enterprise metadata and settings
- Organization configurations and policies
- Repository security settings and best practices
- GitHub Copilot usage and seat allocation
- Branch protection rules
- Security features (Dependabot, secret scanning, code scanning)
- Team structure and permissions
- Budget controls and cost management
- Authentication and SSO configuration
- Audit log events (last 30 days)

SCOPE CONTROL:
- If enterprise is specified -> Scans the enterprise and all its organizations
- If organizations are specified -> Scans only those organizations
- If repositories are specified -> Scans only those specific repositories
- If ghes_instances are specified -> Scans those GitHub Enterprise Server hostnames

OUTPUT FORMATS:
- JSON: Detailed structured data for programmatic analysis

AUTHENTICATION:
- GH_TOKEN/GITHUB_TOKEN must be valid for all specified GitHub.com/GHES targets

The scan produces comprehensive data that can be used to generate:
- Security posture assessments
- Compliance reports
- Cost optimization recommendations
- Best practice gap analysis
- Detailed architecture documentation`),
		mcp.WithArray("enterprises",
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Description("Optional array of enterprise slugs to scan. Each enterprise will be fully scanned including all organizations."),
		),
		mcp.WithArray("organizations",
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Description("Optional array of organization names to scan. Can be used alone or in addition to enterprises."),
		),
		mcp.WithArray("repositories",
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Description("Optional array of repositories to scan in 'owner/repo' format. Use for targeted repository analysis."),
		),
		mcp.WithArray("ghes_instances",
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Description("Optional array of GitHub Enterprise Server hostnames (without protocol) to scan. GH_TOKEN/GITHUB_TOKEN must be valid for all specified instances."),
		),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
	)

	s.AddTool(scan, mcp.NewTypedToolHandler(scanHandler))
}

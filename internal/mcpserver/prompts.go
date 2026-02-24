// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func RegisterPrompts(s *server.MCPServer) {
	scanPrompt := mcp.NewPrompt(
		"scan_github_enterprise",
		mcp.WithPromptDescription("Comprehensive GitHub enterprise/organization scan with detailed architecture report generation"),
		mcp.WithArgument("enterprise", mcp.RequiredArgument()),
	)

	s.AddPrompt(scanPrompt, handleScanPrompt())
}

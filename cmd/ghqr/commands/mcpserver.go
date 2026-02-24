// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"github.com/microsoft/ghqr/internal/mcpserver"
	"github.com/spf13/cobra"
)

var (
	mcpMode string
	mcpAddr string
)

func init() {
	mcpCmd.Flags().StringVar(&mcpMode, "mode", "stdio", "Server mode: stdio (default) or http")
	mcpCmd.Flags().StringVar(&mcpAddr, "addr", ":8080", "Address to listen on (only used in HTTP mode)")
	rootCmd.AddCommand(mcpCmd)
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP server",
	Long: `Start the MCP server in stdio or HTTP/SSE mode.

The MCP (Model Context Protocol) server exposes GitHub Quick Review functionality
as tools and prompts that can be used by AI assistants and other MCP clients.

Available Tools:
  - scan: Comprehensive GitHub enterprise/organization/repository scan

Available Prompts:
  - scan_github_enterprise: Generate detailed architecture reports with
    security findings, cost analysis, and actionable recommendations

Examples:
  # Start in stdio mode (default) - for local MCP clients like Claude Desktop
  ghqr mcp
  
  # Start in HTTP/SSE mode on default port :8080
  ghqr mcp --mode http
  
  # Start in HTTP/SSE mode on custom port
  ghqr mcp --mode http --addr :3000

Configuration:
  The server requires GITHUB_TOKEN environment variable to be set for
  authentication with the GitHub API.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		mode := mcpserver.ServerMode(mcpMode)
		mcpserver.StartWithMode(mode, mcpAddr)
	},
}

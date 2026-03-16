// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/pipeline"
	"github.com/rs/zerolog/log"
)

// ScanArgs represents the arguments for the scan tool
type ScanArgs struct {
	Enterprises   []string `json:"enterprises,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Repositories  []string `json:"repositories,omitempty"`
}

func scanHandler(ctx context.Context, request mcp.CallToolRequest, args ScanArgs) (*mcp.CallToolResult, error) {
	currentDir, err := getCurrentFolder(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get current working directory")
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	// Generate output folder/name if not provided
	outputName := filepath.Join(currentDir, fmt.Sprintf("ghqr_%s", time.Now().Format("20060102_150405")))

	params := models.ScanParams{
		Enterprises:   args.Enterprises,
		Organizations: args.Organizations,
		Repositories:  args.Repositories,
		OutputName:    outputName,
	}

	log.Debug().
		Strs("enterprises", args.Enterprises).
		Strs("organizations", args.Organizations).
		Strs("repositories", args.Repositories).
		Str("output", outputName).
		Msg("Starting GitHub scan")

	output, err := (&pipeline.Scanner{}).Scan(&params)
	if err != nil {
		log.Error().Err(err).Msg("scan failed")
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	jsonPath := output + ".json"
	jsonURI := fileURIToPath(jsonPath)
	registerScanResources(output, "GitHub Quick Review Scan Results", jsonURI)

	// Build the base result; status is set after we confirm the file was written.
	result := map[string]interface{}{
		"outputPath":    output,
		"enterprises":   args.Enterprises,
		"organizations": args.Organizations,
		"repositories":  args.Repositories,
	}

	// Read the report back to return findings inline. A read failure means the
	// write never succeeded; surface that rather than silently reporting "completed".
	jsonBytes, readErr := os.ReadFile(jsonPath)
	if readErr != nil {
		log.Error().Err(readErr).Str("path", jsonPath).Msg("Failed to read JSON report after scan")
		result["status"] = "error"
		result["error"] = fmt.Sprintf("report file could not be read: %s", readErr.Error())
		return mcp.NewToolResultStructured(
			result,
			fmt.Sprintf("Scan failed: report file was not written to %s\nError: %s", jsonPath, readErr.Error()),
		), nil
	}

	result["status"] = "completed"
	toolResult := mcp.NewToolResultStructured(result, fmt.Sprintf("Scan completed successfully. Results saved to:\n%s", jsonURI))
	toolResult.Content = append(toolResult.Content, mcp.NewTextContent(string(jsonBytes)))
	return toolResult, nil
}

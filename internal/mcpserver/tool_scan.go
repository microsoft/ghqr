// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"context"
	"fmt"
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
		Debug:         false,
	}

	log.Debug().
		Strs("enterprises", args.Enterprises).
		Strs("organizations", args.Organizations).
		Strs("repositories", args.Repositories).
		Str("output", outputName).
		Msg("Starting GitHub scan")

	output := (&pipeline.Scanner{}).Scan(&params)
	jsonURI := fmt.Sprintf("file://%s.json", output)

	registerScanResources(output, "GitHub Quick Review Scan Results", jsonURI)

	// Build structured result
	result := map[string]interface{}{
		"status":        "completed",
		"outputPath":    output,
		"enterprises":   args.Enterprises,
		"organizations": args.Organizations,
		"repositories":  args.Repositories,
	}

	return mcp.NewToolResultStructured(result, fmt.Sprintf("Scan completed successfully. Results saved to:\n%s", jsonURI)), nil
}

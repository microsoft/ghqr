// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog/log"
)

// registerScanResources registers JSON scan results as MCP resources
func registerScanResources(outputName, resultName string, uriJSON string) {
	if s == nil {
		return
	}

	// Register JSON resource if it exists
	if _, err := os.Stat(outputName); err != nil {
		return
	}

	jsonResource := mcp.NewResource(
		uriJSON,
		resultName+" (JSON)",
		mcp.WithResourceDescription("The results of the GitHub Quick Review (ghqr) scan (JSON)."),
		mcp.WithMIMEType("application/json"),
	)

	encodedJSON := encodeFileBase64(outputName)
	s.AddResource(jsonResource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.BlobResourceContents{
				URI:      uriJSON,
				MIMEType: "application/json",
				Blob:     encodedJSON,
			},
		}, nil
	})
}

// encodeFileBase64 reads a file and returns its base64-encoded content
func encodeFileBase64(path string) string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("failed to read file for base64 encoding")
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

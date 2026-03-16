// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// fileURIToPath converts a file:// URI to an OS filesystem path.
// e.g. "file:///home/user/dir" -> "/home/user/dir" (Linux)
// e.g. "file:///C:/Users/dir"  -> "C:\Users\dir"  (Windows)
func fileURIToPath(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid file URI %q: %w", uri, err)
	}
	p := parsed.Path
	// On Windows, url.Parse("file:///C:/path") gives Path="/C:/path".
	// Strip the leading slash before the drive letter.
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), nil
}

// pathToFileURI converts an OS filesystem path to a file:// URI.
// e.g. "/home/user/file.json"    -> "file:///home/user/file.json" (Linux)
// e.g. "C:\Users\file.json"      -> "file:///C:/Users/file.json"  (Windows)
func pathToFileURI(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		// Windows absolute path like "C:/Users/..." needs a leading slash
		p = "/" + p
	}
	return "file://" + p
}

func currentWorkspace(ctx context.Context) string {
	result, err := s.RequestRoots(ctx, mcp.ListRootsRequest{})
	if err == nil {
		for _, root := range result.Roots {
			uri := root.URI
			if strings.HasPrefix(uri, "file://") {
				path, err := fileURIToPath(uri)
				if err != nil {
					continue
				}
				return path
			}
		}
	}

	return ""
}

func getCurrentFolder(ctx context.Context) (string, error) {
	if currentDir := currentWorkspace(ctx); currentDir != "" {
		return currentDir, nil
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	return currentDir, nil
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

func TestRegisterToolsScanIncludesGHESInstances(t *testing.T) {
	s := server.NewMCPServer("test", "test")
	RegisterTools(s)

	scanTool := s.GetTool("scan")
	if scanTool == nil {
		t.Fatal("scan tool not registered")
	}

	if _, ok := scanTool.Tool.InputSchema.Properties["ghes_instances"]; !ok {
		t.Fatal("scan tool missing ghes_instances parameter")
	}
}

func TestScanArgsUnmarshalGHESInstances(t *testing.T) {
	var args ScanArgs
	if err := json.Unmarshal([]byte(`{"ghes_instances":["ghes1.example.com","ghes2.example.com"]}`), &args); err != nil {
		t.Fatalf("failed to unmarshal scan args: %v", err)
	}

	expected := []string{"ghes1.example.com", "ghes2.example.com"}
	if !reflect.DeepEqual(expected, args.GHESInstances) {
		t.Fatalf("unexpected GHES instances: got %v, want %v", args.GHESInstances, expected)
	}
}

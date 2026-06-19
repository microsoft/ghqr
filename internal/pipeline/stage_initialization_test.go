// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"net/http"
	"testing"
)

func TestIsGitHubAppUserEndpointForbidden(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{
			name:       "returns true for forbidden status",
			statusCode: http.StatusForbidden,
			want:       true,
		},
		{
			name:       "returns false for unauthorized status",
			statusCode: http.StatusUnauthorized,
			want:       false,
		},
		{
			name:       "returns false for success status",
			statusCode: http.StatusOK,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGitHubAppUserEndpointForbidden(tt.statusCode); got != tt.want {
				t.Fatalf("isGitHubAppUserEndpointForbidden(%d) = %t, want %t", tt.statusCode, got, tt.want)
			}
		})
	}
}

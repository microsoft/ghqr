// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package models

type ScanParams struct {
	Enterprises   []string
	Organizations []string
	Repositories  []string
	OutputName    string
	Hostname      string
	Debug         bool
	Xlsx          bool
	Markdown      bool
	// FromJSON, when set, points to an existing scan JSON file. The pipeline
	// loads results from this file and skips all GitHub API scan stages,
	// re-running only enrichment (evaluation) and report rendering.
	FromJSON string
}

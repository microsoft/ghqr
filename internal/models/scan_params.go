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
}

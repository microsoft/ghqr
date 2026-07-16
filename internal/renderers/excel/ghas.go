// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"sort"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
)

// renderGHAS writes the GHAS sheet, showing the enterprise-wide GitHub Advanced
// Security policy defaults that cascade to all organizations.
func renderGHAS(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "GHAS"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create GHAS sheet")
		return
	}

	headers := []string{
		"Enterprise", "Advanced Security", "Secret Scanning",
		"Secret Scanning Push Protection", "Dependabot Alerts",
		"Dependabot Security Updates", "Dependency Graph",
		"Secret Scanning Non-Provider Patterns",
	}

	data := buildGHASTable(results)
	rows := make([][]string, 0, len(data)+1)
	rows = append(rows, headers)
	rows = append(rows, data...)
	streamSheet(f, sheet, rows, styles)
}

// ghasVal normalizes a GHAS policy value for display. Empty values are shown as
// "not_set" to match GitHub's own terminology.
func ghasVal(v string) string {
	if v == "" {
		return "not_set"
	}
	return v
}

func buildGHASTable(results map[string]interface{}) [][]string {
	type row struct {
		name string
		cols []string
	}

	var rows []row

	for key, val := range results {
		if !strings.HasPrefix(key, "enterprise:") {
			continue
		}
		name := strings.TrimPrefix(key, "enterprise:")
		entData := asType[scanners.EnterpriseData](val)
		if entData == nil {
			continue
		}

		s := entData.GHASSettings
		if s == nil {
			// Endpoint not accessible (requires enterprise admin token); still
			// list the enterprise so its absence is explicit.
			na := "Not available"
			rows = append(rows, row{name: name, cols: []string{
				name, na, na, na, na, na, na, na,
			}})
			continue
		}

		rows = append(rows, row{name: name, cols: []string{
			name,
			ghasVal(s.AdvancedSecurity),
			ghasVal(s.SecretScanning),
			ghasVal(s.SecretScanningPushProtection),
			ghasVal(s.DependabotAlerts),
			ghasVal(s.DependabotSecurityUpdates),
			ghasVal(s.DependencyGraph),
			ghasVal(s.SecretScanningNonProviderPatterns),
		}})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
)

// StyleCache holds pre-created style IDs for reuse across all sheets.
type StyleCache struct {
	Header int
	Blue   int
	White  int
}

// createSharedStyles creates all shared styles once and caches their IDs.
func createSharedStyles(f *excelize.File) (*StyleCache, error) {
	header, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#CAEDFB"},
			Pattern: 1,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create header style: %w", err)
	}

	blue, err := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#CAEDFB"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create blue style: %w", err)
	}

	white, err := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "top", WrapText: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create white style: %w", err)
	}

	return &StyleCache{Header: header, Blue: blue, White: white}, nil
}

// CreateExcelReport builds an Excel file from scan results and writes it to disk.
func CreateExcelReport(results map[string]interface{}, outputName string) {
	filename := fmt.Sprintf("%s.xlsx", outputName)
	log.Info().Msgf("Generating Excel report: %s", filename)

	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close Excel file")
		}
	}()

	styles, err := createSharedStyles(f)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create shared styles")
		return
	}

	renderOrganizations(f, results, styles)
	renderRepositories(f, results, styles)
	renderBranchProtection(f, results, styles)
	renderIssues(f, results, styles)

	// Remove the default empty "Sheet1" that excelize creates.
	sheets := f.GetSheetList()
	if len(sheets) > 1 {
		if err := f.DeleteSheet("Sheet1"); err != nil {
			log.Warn().Err(err).Msg("Failed to delete default sheet")
		}
	}

	if err := f.SaveAs(filename); err != nil {
		log.Fatal().Err(err).Msg("Failed to save Excel file") //nolint:gocritic
	}

	log.Info().Str("path", filename).Msg("Excel report written")
}

// createFirstRow writes the header row (row 1) and applies the header style.
func createFirstRow(f *excelize.File, sheet string, headers []string, styles *StyleCache) {
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get cell")
	}
	if err := f.SetSheetRow(sheet, cell, &headers); err != nil {
		log.Fatal().Err(err).Msg("Failed to set header row")
	}
	if len(headers) > 0 {
		endCell, err := excelize.CoordinatesToCellName(len(headers), 1)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get end cell")
		}
		if err := f.SetCellStyle(sheet, "A1", endCell, styles.Header); err != nil {
			log.Fatal().Err(err).Msg("Failed to set header style")
		}
	}
}

// writeRows appends rows starting after startRow and returns the last written row number.
func writeRows(f *excelize.File, sheet string, rows [][]string, startRow int) (int, error) {
	currentRow := startRow
	for _, row := range rows {
		currentRow++
		cell, err := excelize.CoordinatesToCellName(1, currentRow)
		if err != nil {
			return currentRow, fmt.Errorf("failed to get cell name: %w", err)
		}
		if err := f.SetSheetRow(sheet, cell, &row); err != nil {
			return currentRow, fmt.Errorf("failed to set row: %w", err)
		}
	}
	return currentRow, nil
}

// configureSheet applies autofit, autofilter, and alternating row colors.
func configureSheet(f *excelize.File, sheet string, headers []string, lastRow int, styles *StyleCache) {
	autofitColumns(f, sheet)

	if len(headers) > 0 && lastRow >= 1 {
		endCell, err := excelize.CoordinatesToCellName(len(headers), lastRow)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get autofilter end cell")
		}
		if err := f.AutoFilter(sheet, fmt.Sprintf("A1:%s", endCell), nil); err != nil {
			log.Fatal().Err(err).Msg("Failed to set autofilter")
		}
	}

	applyRowStyles(f, sheet, lastRow, len(headers), styles)
}

// autofitColumns sets column widths based on content (sampled, capped at 120).
func autofitColumns(f *excelize.File, sheet string) {
	cols, err := f.GetCols(sheet)
	if err != nil {
		return
	}
	const maxWidth = 120
	const sampleRows = 1000
	for idx, col := range cols {
		largest := 0
		limit := len(col)
		if limit > sampleRows {
			limit = sampleRows
		}
		for i := 0; i < limit; i++ {
			w := len(col[i]) + 3
			if w > largest {
				largest = w
			}
			if largest >= maxWidth {
				largest = maxWidth
				break
			}
		}
		if largest > 255 {
			largest = maxWidth
		}
		name, err := excelize.ColumnNumberToName(idx + 1)
		if err != nil {
			continue
		}
		_ = f.SetColWidth(sheet, name, name, float64(largest))
	}
}

// applyRowStyles applies alternating blue/white fill to data rows (row 2 onward).
func applyRowStyles(f *excelize.File, sheet string, lastRow, columns int, styles *StyleCache) {
	if columns == 0 || lastRow < 2 {
		return
	}
	for i := 2; i <= lastRow; i++ {
		style := styles.White
		if i%2 == 0 {
			style = styles.Blue
		}
		startCell, err := excelize.CoordinatesToCellName(1, i)
		if err != nil {
			continue
		}
		endCell, err := excelize.CoordinatesToCellName(columns, i)
		if err != nil {
			continue
		}
		if err := f.SetCellStyle(sheet, startCell, endCell, style); err != nil {
			log.Fatal().Err(err).Msg("Failed to set row style")
		}
	}
}

// boolStr converts a bool to "Yes" / "No" for human-readable output.
func boolStr(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

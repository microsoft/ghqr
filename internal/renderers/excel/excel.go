// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"fmt"
	"strconv"

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
	filename := outputName + ".xlsx"
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

// streamSheet writes all rows for a sheet using excelize StreamWriter, which streams
// directly to the zip buffer instead of keeping every cell in an in-memory map.
// rows[0] is treated as the header row. Column widths are pre-computed from the
// in-memory slice so no second read-back of the sheet is required.
func streamSheet(f *excelize.File, sheetName string, rows [][]string, styles *StyleCache) {
	if len(rows) == 0 {
		return
	}

	widths := computeWidthsFromRecords(rows, 1000)

	sw, err := f.NewStreamWriter(sheetName)
	if err != nil {
		log.Error().Err(err).Msgf("failed to create stream writer for %s", sheetName)
		return
	}

	// Column widths must be set before any SetRow calls.
	for i, w := range widths {
		if w < 8 {
			w = 8
		}
		if err := sw.SetColWidth(i+1, i+1, float64(w)); err != nil {
			log.Warn().Err(err).Msgf("failed to set column %d width for %s", i+1, sheetName)
		}
	}

	// Header row (row 1).
	headers := rows[0]
	headerCells := make([]interface{}, len(headers))
	for i, h := range headers {
		headerCells[i] = excelize.Cell{Value: h, StyleID: styles.Header}
	}
	if err := sw.SetRow("A1", headerCells, excelize.RowOpts{StyleID: styles.Header}); err != nil {
		log.Error().Err(err).Msgf("failed to write header row for %s", sheetName)
	}

	// Data rows with alternating blue/white fill.
	cells := make([]interface{}, len(headers))
	for i, row := range rows[1:] {
		rowNum := i + 2 // 1-based; header is row 1
		styleID := styles.White
		if rowNum%2 == 0 {
			styleID = styles.Blue
		}
		for j := range cells {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			cells[j] = excelize.Cell{Value: val, StyleID: styleID}
		}
		cellName := "A" + strconv.Itoa(rowNum)
		if err := sw.SetRow(cellName, cells, excelize.RowOpts{StyleID: styleID}); err != nil {
			log.Warn().Err(err).Msgf("failed to write row %d for %s", rowNum, sheetName)
		}
	}

	// AutoFilter must be applied before Flush so it is serialised into the worksheet XML.
	if len(rows) >= 1 && len(headers) > 0 {
		lastRow := len(rows)
		if lastCell, err := excelize.CoordinatesToCellName(len(headers), lastRow); err == nil {
			if err := f.AutoFilter(sheetName, "A1:"+lastCell, nil); err != nil {
				log.Warn().Err(err).Msgf("failed to set autofilter for %s", sheetName)
			}
		}
	}

	if err := sw.Flush(); err != nil {
		log.Error().Err(err).Msgf("failed to flush stream writer for %s", sheetName)
	}
}

// computeWidthsFromRecords calculates per-column max widths by scanning the
// already-in-memory records slice. This avoids the memory cost of f.GetCols()
// which reads all sheet data back out of excelize's cell map.
// At most maxSampleRows rows are scanned to bound the cost for large sheets.
func computeWidthsFromRecords(records [][]string, maxSampleRows int) []int {
	if len(records) == 0 {
		return nil
	}
	const maxWidth = 120
	ncols := len(records[0])
	widths := make([]int, ncols)

	limit := len(records)
	if limit > maxSampleRows {
		limit = maxSampleRows
	}

	for _, row := range records[:limit] {
		for i, cell := range row {
			if i >= ncols {
				break
			}
			w := len(cell) + 3
			if w > widths[i] {
				widths[i] = w
			}
			if widths[i] > maxWidth {
				widths[i] = maxWidth
			}
		}
	}
	return widths
}

// boolStr converts a bool to "Yes" / "No" for human-readable output.
func boolStr(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

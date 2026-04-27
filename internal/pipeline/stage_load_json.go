// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

// LoadFromJSONStage replays a previous scan by loading its JSON output into
// ctx.Results. When active, all scanning stages skip themselves so that only
// evaluation and report rendering run against the loaded data.
type LoadFromJSONStage struct {
	*BaseStage
}

// NewLoadFromJSONStage creates a new load-from-json stage.
func NewLoadFromJSONStage() *LoadFromJSONStage {
	return &LoadFromJSONStage{
		BaseStage: NewBaseStage("load-from-json"),
	}
}

// embeddedEvalFields lists fields the JSON renderer embeds into entities from
// prior evaluation runs. They are stripped on load so a replay produces a
// clean output instead of nesting evaluations inside evaluations.
var embeddedEvalFields = []string{
	"evaluation",
	"copilot_evaluation",
	"actions_permissions_evaluation",
	"org_security_alerts_evaluation",
	"security_managers_evaluation",
	"enterprise_security_alerts_evaluation",
	"enterprise_ghas_evaluation",
	"org_security_defaults_evaluation",
	"audit_log_evaluation",
	"metadata_evaluation",
	"collaborators_evaluation",
	"deploy_keys_evaluation",
	"dependabot_evaluation",
	"code_scanning_evaluation",
	"discussions_evaluation",
}

func (s *LoadFromJSONStage) Execute(ctx *ScanContext) error {
	path := ctx.Params.FromJSON
	log.Info().Str("path", path).Msg("Replaying scan from JSON; GitHub API calls will be skipped")

	data, err := os.ReadFile(path) // #nosec G304 -- user-supplied input file is the documented interface
	if err != nil {
		return fmt.Errorf("failed to read --from-json file %q: %w", path, err)
	}

	var report struct {
		Enterprises   map[string]interface{} `json:"enterprises"`
		Organizations map[string]interface{} `json:"organizations"`
		Repositories  map[string]interface{} `json:"repositories"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("failed to parse --from-json file %q: %w", path, err)
	}

	loaded := loadEntities(ctx, "enterprise:", report.Enterprises) +
		loadEntities(ctx, "organization:", report.Organizations) +
		loadEntities(ctx, "repository:", report.Repositories)

	if loaded == 0 {
		return fmt.Errorf("no entities found in %q (expected 'enterprises', 'organizations', or 'repositories' keys)", path)
	}

	// Warn once about lossy fields that the JSON renderer compacts on output.
	for _, entity := range report.Repositories {
		if m, ok := entity.(map[string]interface{}); ok {
			if _, has := m["collaborator_summary"]; has {
				log.Warn().Msg("Replay input contains 'collaborator_summary' (compacted); per-collaborator rules will not be re-evaluated")
				break
			}
		}
	}

	log.Info().
		Int("enterprises", len(report.Enterprises)).
		Int("organizations", len(report.Organizations)).
		Int("repositories", len(report.Repositories)).
		Msg("Replay data loaded")
	return nil
}

func loadEntities(ctx *ScanContext, prefix string, entities map[string]interface{}) int {
	count := 0
	for name, raw := range entities {
		m, ok := raw.(map[string]interface{})
		if !ok {
			log.Warn().Str("entity", prefix+name).Msg("Skipping entity with unexpected JSON shape")
			continue
		}
		for _, field := range embeddedEvalFields {
			delete(m, field)
		}
		ctx.Results[prefix+name] = m
		count++
	}
	return count
}

// Skip returns true when --from-json is not supplied.
func (s *LoadFromJSONStage) Skip(ctx *ScanContext) bool {
	return ctx.Params == nil || ctx.Params.FromJSON == ""
}

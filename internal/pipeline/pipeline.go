// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package pipeline provides a composable pipeline pattern for the scan execution flow.
package pipeline

import (
	"context"
	"net/http"
	"time"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/models"
	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
)

// ScanContext holds the state shared across pipeline stages.
type ScanContext struct {
	Ctx       context.Context
	Cancel    context.CancelFunc
	StartTime time.Time
	// OutputDir is computed once at startup and used by all stages.
	OutputName          string
	Params              *models.ScanParams
	GitHubClient        *github.Client
	GitHubGraphQLClient *githubv4.Client
	// GitHubRawHTTPClient is the underlying HTTP client used by GitHubGraphQLClient.
	// It shares the same auth and rate-limit transport, and is used for batch queries.
	GitHubRawHTTPClient *http.Client
	// Results accumulates scan data for report rendering.
	// Keys follow the pattern "type:name", e.g. "organization:my-org", "repository:owner/repo".
	Results map[string]interface{}
	// Ownership tracks parent/child relationships discovered during scanning.
	// Keys are "organization:<login>" and values are the enterprise slug that owns the org.
	Ownership map[string]string
}

// Stage represents a single stage in the scan pipeline.
type Stage interface {
	Name() string
	Execute(ctx *ScanContext) error
	Skip(ctx *ScanContext) bool
}

// Pipeline orchestrates the execution of multiple stages in sequence.
type Pipeline struct {
	stages  []Stage
	metrics *PipelineMetrics
}

// PipelineMetrics tracks performance of each pipeline stage.
type PipelineMetrics struct {
	TotalDuration  time.Duration
	StageDurations map[string]time.Duration
	StagesExecuted int
	StagesSkipped  int
}

// NewPipeline creates a new scan pipeline with the given stages.
func NewPipeline(stages ...Stage) *Pipeline {
	return &Pipeline{
		stages: stages,
		metrics: &PipelineMetrics{
			StageDurations: make(map[string]time.Duration),
		},
	}
}

// Execute runs all pipeline stages in sequence.
func (p *Pipeline) Execute(ctx *ScanContext) error {
	startTime := time.Now()
	log.Info().
		Int("stages", len(p.stages)).
		Msg("Scan started")

	for i, stage := range p.stages {
		stageName := stage.Name()

		if stage.Skip(ctx) {
			log.Debug().
				Str("stage", stageName).
				Int("position", i+1).
				Msg("Skipping stage")
			p.metrics.StagesSkipped++
			continue
		}

		log.Debug().
			Str("stage", stageName).
			Int("position", i+1).
			Int("total", len(p.stages)).
			Msg("Executing stage")

		stageStart := time.Now()
		err := stage.Execute(ctx)
		stageDuration := time.Since(stageStart)

		p.metrics.StageDurations[stageName] = stageDuration
		p.metrics.StagesExecuted++

		if err != nil {
			log.Error().
				Err(err).
				Str("stage", stageName).
				Dur("duration", stageDuration).
				Msg("Stage failed")
			return err
		}

		log.Debug().
			Str("stage", stageName).
			Dur("duration", stageDuration).
			Msg("Stage completed")
	}

	p.metrics.TotalDuration = time.Since(startTime)

	log.Debug().
		Dur("total_duration", p.metrics.TotalDuration).
		Int("executed", p.metrics.StagesExecuted).
		Int("skipped", p.metrics.StagesSkipped).
		Msg("Scan completed")

	return nil
}

// LogMetrics logs detailed pipeline metrics.
func (p *Pipeline) LogMetrics() {
	log.Debug().Msg("=== Scan Performance Metrics ===")
	for i, stage := range p.stages {
		stageName := stage.Name()
		if duration, ok := p.metrics.StageDurations[stageName]; ok {
			percentage := float64(duration) / float64(p.metrics.TotalDuration) * 100
			log.Debug().
				Int("position", i+1).
				Str("stage", stageName).
				Dur("duration", duration).
				Float64("percentage", percentage).
				Msg("Stage metrics")
		}
	}
	log.Debug().
		Dur("total", p.metrics.TotalDuration).
		Int("executed", p.metrics.StagesExecuted).
		Int("skipped", p.metrics.StagesSkipped).
		Msg("=== End Scan Metrics ===")
}

// BaseStage provides a default Name() implementation for the Stage interface.
type BaseStage struct {
	name string
}

func NewBaseStage(name string) *BaseStage {
	return &BaseStage{name: name}
}

func (s *BaseStage) Name() string {
	return s.name
}

func (s *BaseStage) Skip(_ *ScanContext) bool {
	return false
}

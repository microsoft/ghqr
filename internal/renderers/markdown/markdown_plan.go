// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"sort"
	"strings"
)

// generateRemediationPlan builds the 30/60/90-day remediation plan.
func generateRemediationPlan(allFindings []entityFindings) string {
	var sprint30, sprint60, sprint90 []planItem

	for _, ef := range allFindings {
		for _, r := range ef.Findings {
			item := planItem{Entity: ef.EntityName, Rec: r}
			switch r.Severity {
			case "critical", "high":
				sprint30 = append(sprint30, item)
			case "medium":
				sprint60 = append(sprint60, item)
			case "low", "info":
				sprint90 = append(sprint90, item)
			}
		}
	}

	// Sort each sprint by severity then entity.
	sortItems := func(items []planItem) {
		sort.Slice(items, func(i, j int) bool {
			if severityOrder[items[i].Rec.Severity] != severityOrder[items[j].Rec.Severity] {
				return severityOrder[items[i].Rec.Severity] < severityOrder[items[j].Rec.Severity]
			}
			return items[i].Entity < items[j].Entity
		})
	}
	sortItems(sprint30)
	sortItems(sprint60)
	sortItems(sprint90)

	var sb strings.Builder

	// 30-Day Sprint
	sb.WriteString("### 30-Day Sprint — Immediate Actions 🔴\n\n")
	sb.WriteString("> Address all **critical** and **high** severity issues. These represent the\n")
	sb.WriteString("> highest risk to your organization and should be resolved within the first month.\n\n")
	sb.WriteString(renderPlanTable(sprint30))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Eliminate all %d critical and high-severity risks, establishing a secure baseline for branch protection, vulnerability scanning, and access controls.\n\n---\n\n", len(sprint30)))

	// 60-Day Sprint
	sb.WriteString("### 60-Day Sprint — High-Priority Improvements 🟠\n\n")
	sb.WriteString("> Address all **medium** severity issues and any high-effort critical/high fixes\n")
	sb.WriteString("> that couldn't be completed in the 30-day sprint.\n\n")
	sb.WriteString(renderPlanTable(sprint60))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Close all %d medium-severity gaps, improving governance, access controls, and cost optimization across the environment.\n\n---\n\n", len(sprint60)))

	// 90-Day Sprint
	sb.WriteString("### 90-Day Sprint — Strategic Hardening 🟡\n\n")
	sb.WriteString("> Address all **low** severity issues, implement process improvements, and\n")
	sb.WriteString("> establish ongoing governance controls.\n\n")
	sb.WriteString(renderPlanTable(sprint90))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Complete all %d remaining improvements, achieving a fully hardened environment with community health documentation, automated branch cleanup, and long-term maintenance practices.\n\n", len(sprint90)))

	return sb.String()
}

// renderPlanTable renders the priority action table for a sprint.
func renderPlanTable(items []planItem) string {
	if len(items) == 0 {
		return "*No items in this phase.*\n"
	}

	var sb strings.Builder
	sb.WriteString("| Priority | Entity | Action | Category | Effort | Owner |\n")
	sb.WriteString("|----------|--------|--------|----------|--------|-------|\n")

	// Deduplicate: group same issue+category across entities.
	type dedupeKey struct {
		Issue    string
		Category string
	}
	entitySets := map[dedupeKey]map[string]struct{}{}
	recByKey := map[dedupeKey]recommendation{}
	keyOrder := make([]dedupeKey, 0, len(items))

	for _, item := range items {
		key := dedupeKey{Issue: item.Rec.Issue, Category: item.Rec.Category}
		if _, ok := entitySets[key]; !ok {
			entitySets[key] = map[string]struct{}{}
			recByKey[key] = item.Rec
			keyOrder = append(keyOrder, key)
		}
		entitySets[key][item.Entity] = struct{}{}
	}

	priority := 1
	for _, key := range keyOrder {
		entitySet := entitySets[key]
		uniqueEntities := make([]string, 0, len(entitySet))
		for e := range entitySet {
			uniqueEntities = append(uniqueEntities, e)
		}
		sort.Strings(uniqueEntities)

		rec := recByKey[key]
		effort := estimateEffort(rec)
		displayCat := categoryDisplayNames[rec.Category]
		if displayCat == "" {
			displayCat = rec.Category
		}

		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n",
			priority,
			strings.Join(uniqueEntities, ", "),
			rec.Recommendation,
			displayCat,
			effort,
			suggestOwner(rec.Category),
		))
		priority++
	}

	return sb.String()
}

// estimateEffort provides S/M/L effort estimate based on the recommendation type.
func estimateEffort(rec recommendation) string {
	issue := strings.ToLower(rec.Issue)
	recommendation := strings.ToLower(rec.Recommendation)
	combined := issue + " " + recommendation

	// Large effort: requires team coordination or phased rollout.
	if strings.Contains(combined, "archive") || strings.Contains(combined, "phased") ||
		strings.Contains(combined, "coordinate") || strings.Contains(combined, "migration") {
		return "L — Large"
	}

	// Small effort: single toggle or setting change.
	if strings.Contains(combined, "enable") || strings.Contains(combined, "toggle") ||
		strings.Contains(combined, "switch to") || strings.Contains(combined, "restrict") ||
		strings.Contains(combined, "require") || strings.Contains(combined, "reclaim") {
		return "S — Small"
	}

	// Medium effort: creating files or policies.
	if strings.Contains(combined, "add a") || strings.Contains(combined, "create") ||
		strings.Contains(combined, "codeowners") || strings.Contains(combined, "security.md") ||
		strings.Contains(combined, "description") || strings.Contains(combined, "topics") {
		return "M — Medium"
	}

	return "M — Medium"
}

// suggestOwner suggests a responsible team based on the category.
func suggestOwner(category string) string {
	owners := map[string]string{
		"security":           "Security Team",
		"branch_protection":  "Platform / DevOps",
		"access_control":     "Security Team",
		"copilot_security":   "Platform / DevOps",
		"copilot_cost":       "Engineering Managers",
		"copilot_features":   "Platform / DevOps",
		"copilot_models":     "Platform / DevOps",
		"copilot_mcp":        "Platform / DevOps",
		"copilot_extensions": "Platform / DevOps",
		"actions":            "Platform / DevOps",
		"community":          "Repository Owners",
		"dependencies":       "Security Team",
		"permissions":        "Security Team",
		"deployment":         "Platform / DevOps",
		"maintenance":        "Repository Owners",
		"risk":               "Security Team",
		"features":           "Security Team",
	}
	if owner, ok := owners[category]; ok {
		return owner
	}
	return "Engineering Team"
}

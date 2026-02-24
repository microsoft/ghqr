// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

func handleScanPrompt() func(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		enterprise := request.Params.Arguments["enterprise"]

		prompt := `Perform a comprehensive GitHub Quick Review (ghqr) scan for enterprise '%s'.

Please:
1. Use the scan tool to analyze GitHub resources, focusing on:
   - Enterprise and organization configurations
   - Repository security settings and best practices
   - GitHub Copilot usage and optimization
   - Team structure and permissions
   - Cost management and budget controls
   - Authentication and compliance settings

2. Generate a detailed architecture report following this structure:

# GitHub Enterprise Architecture Report
**Enterprise/Organization:** [Name]
**Generated:** [Date]
**Report Period:** Last 30 days

---

## Executive Summary Dashboard

### Enterprise/Organization Overview
- Name and key metadata
- Total repositories and visibility breakdown
- Team size and member count
- Creation date
- GitHub Copilot licenses (if applicable)
  - Total seats
  - Active vs inactive this cycle
  - Utilization percentage

---

## 🚨 Critical Security Findings

#### HIGH SEVERITY ISSUES
Identify and list all critical security issues such as:
- Two-factor authentication status
- Branch protection policies
- Dependabot alerts status
- Secret scanning configuration
- Code scanning (SAST) status
- Advanced Security enablement

#### MEDIUM SEVERITY ISSUES
List medium-priority security concerns:
- Web commit signoff requirements
- Repository creation permissions
- Forking policies
- Content exclusions for Copilot

---

## 📊 Repository Security Analysis

### Repository Overview
Create a table of all repositories with:
- Repository name
- Primary language
- Number of issues by severity
- Repository size

### Common Security Gaps
Identify patterns across repositories:
- ❌ Disabled features (Advanced Security, Dependabot, Secret Scanning, Code Scanning)
- ❌ Missing configurations (Branch protection, SECURITY.md, Actions restrictions)
- ⚠️ Security concerns (Forking settings, commit signoff, workflow permissions)

---

## 🤖 GitHub Copilot Analysis (if applicable)

### Current Configuration
Analyze:
- Seat management policy
- Active vs inactive users
- User activity and editor usage
- Public code suggestions setting
- Model restrictions
- Content exclusions
- MCP extensions status

### Recommendations
Prioritize by:
- HIGH: Security and compliance gaps
- MEDIUM: Cost optimization opportunities
- LOW: Feature enablement suggestions

---

## 💰 Cost & Budget Management

### Configured Budgets
List spending limits for:
- GitHub Actions
- Packages
- Codespaces
- Git LFS
- Other services

### Advanced Security Status
Report on:
- Maximum committers
- Active committers
- Repositories with Advanced Security enabled

---

## 🔐 Authentication & Compliance

### Identity Provider
- SSO integration status
- External identity provider details
- User authentication coverage

### Recent Authentication Activity
Highlight any:
- Unusual login patterns
- Country/location changes
- OAuth application activity

### OAuth Applications Activity
List recent OAuth events and authorizations

---

## 📋 Enterprise/Organization Policies

### Actions Permissions
- Allowed actions configuration
- Workflow permissions
- SHA pinning requirements

### Organization Settings
Audit key settings:
- Default repository permissions
- Repository creation policies
- Forking policies
- Project settings

### Rulesets
List active and inactive rulesets

---

## 🎯 Priority Action Plan

### Phase 1: Immediate Actions (Week 1) 🔴
List critical security controls that need immediate attention

### Phase 2: High Priority (Month 1) 🟠
Include branch protection, code quality, and security policies

### Phase 3: Medium Priority (Quarter 1) 🟡
Cover enhanced security, compliance, and optimization

---

## 📈 Expected Impact

### Security Posture Improvement
Describe the expected improvement after implementing the action plan:
- After Phase 1 implementation
- After Phase 2 implementation  
- After Phase 3 implementation

### Risk Reduction
Quantify risk reduction by category

### Cost Impact
Estimate:
- Annual costs
- Potential savings
- ROI on security investments

---

## 📊 Audit Log Summary (Last 30 Days)

### Activity Breakdown
Summarize by category:
- Authentication events
- Administrative changes
- Security events
- Unusual patterns

### Suspicious Activity Detection
Flag any concerning patterns

---

## 🔧 Technical Environment

### Repository Stack
- Programming languages used
- Default branch naming
- Visibility policies
- Total storage used

### Integration Activity
- Active integrations
- Editor usage patterns

---

## 📞 Recommended Next Steps

### Immediate Discussion Topics
List top 3-5 items for stakeholder discussion

### Required Decisions
Create checklist of decisions needed

### Resources Needed
Estimate time, access, and resources required

---

## 📚 References & Documentation
Provide relevant GitHub documentation links

---

## Appendix: Detailed Repository Information

### Active Repositories
Provide detailed breakdown of each repository

### Inactive/Empty Repositories
List candidates for archiving

---

3. Provide actionable recommendations prioritized by:
   - Security impact and urgency
   - Cost optimization potential
   - Quick wins vs long-term improvements
   - Compliance requirements

4. Use specific metrics and evidence from the scan results to support all findings and recommendations.
`

		promptText := fmt.Sprintf(prompt, enterprise)
		promptMessage := mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(promptText))

		return mcp.NewGetPromptResult(
			"GitHub Quick Review: Comprehensive Enterprise Scan",
			[]mcp.PromptMessage{promptMessage},
		), nil
	}
}

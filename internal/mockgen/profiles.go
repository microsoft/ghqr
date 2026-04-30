// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mockgen

import "fmt"

// Profile controls how strict or lax the synthesized facts are. It biases the
// random distribution of fields so that the downstream evaluation stage emits
// a realistic mix of findings.
type Profile string

const (
	// ProfileClean produces entities that pass most rules.
	ProfileClean Profile = "clean"
	// ProfileTypical produces a realistic mix of compliant and non-compliant entities.
	ProfileTypical Profile = "typical"
	// ProfileNoisy produces entities that fail many rules; useful for stress-testing reports.
	ProfileNoisy Profile = "noisy"
)

// profileWeights expresses, per profile, the probability (0..1) that a given
// "compliant" fact will be set to its compliant value. A higher value means
// fewer findings; a lower value means more findings.
type profileWeights struct {
	// Org-level
	twoFactorRequired        float64
	webCommitSignoffRequired float64
	restrictPublicRepoCreate float64
	restrictiveDefaultPerm   float64
	securityManagerAssigned  float64
	actionsLocalOnly         float64
	copilotAssignSelected    float64
	copilotPublicSuggBlocked float64
	advancedSecurityNewRepos float64
	dependabotAlertsNewRepos float64
	secretScanningNewRepos   float64
	pushProtectionNewRepos   float64
	// Repo-level
	hasDescription          float64
	hasTopics               float64
	branchProtected         float64
	dependabotAlertsEnabled float64
	securityPolicyExists    float64
	codeOwnersExists        float64
	deleteBranchOnMerge     float64
	dependabotConfigExists  float64
	hasIssuesOrDiscussions  float64
	// Open alert volume bias (max value for random open alert counts)
	maxOpenAlerts int
}

func weightsFor(p Profile) (profileWeights, error) {
	switch p {
	case ProfileClean:
		return profileWeights{
			twoFactorRequired:        0.95,
			webCommitSignoffRequired: 0.9,
			restrictPublicRepoCreate: 0.95,
			restrictiveDefaultPerm:   0.95,
			securityManagerAssigned:  0.95,
			actionsLocalOnly:         0.85,
			copilotAssignSelected:    0.9,
			copilotPublicSuggBlocked: 0.9,
			advancedSecurityNewRepos: 0.9,
			dependabotAlertsNewRepos: 0.95,
			secretScanningNewRepos:   0.9,
			pushProtectionNewRepos:   0.9,
			hasDescription:           0.95,
			hasTopics:                0.9,
			branchProtected:          0.95,
			dependabotAlertsEnabled:  0.95,
			securityPolicyExists:     0.9,
			codeOwnersExists:         0.85,
			deleteBranchOnMerge:      0.9,
			dependabotConfigExists:   0.85,
			hasIssuesOrDiscussions:   0.95,
			maxOpenAlerts:            2,
		}, nil
	case ProfileTypical, "":
		return profileWeights{
			twoFactorRequired:        0.6,
			webCommitSignoffRequired: 0.4,
			restrictPublicRepoCreate: 0.6,
			restrictiveDefaultPerm:   0.7,
			securityManagerAssigned:  0.5,
			actionsLocalOnly:         0.4,
			copilotAssignSelected:    0.45,
			copilotPublicSuggBlocked: 0.5,
			advancedSecurityNewRepos: 0.55,
			dependabotAlertsNewRepos: 0.65,
			secretScanningNewRepos:   0.55,
			pushProtectionNewRepos:   0.5,
			hasDescription:           0.7,
			hasTopics:                0.55,
			branchProtected:          0.5,
			dependabotAlertsEnabled:  0.55,
			securityPolicyExists:     0.45,
			codeOwnersExists:         0.4,
			deleteBranchOnMerge:      0.55,
			dependabotConfigExists:   0.5,
			hasIssuesOrDiscussions:   0.85,
			maxOpenAlerts:            10,
		}, nil
	case ProfileNoisy:
		return profileWeights{
			twoFactorRequired:        0.1,
			webCommitSignoffRequired: 0.1,
			restrictPublicRepoCreate: 0.15,
			restrictiveDefaultPerm:   0.2,
			securityManagerAssigned:  0.1,
			actionsLocalOnly:         0.1,
			copilotAssignSelected:    0.1,
			copilotPublicSuggBlocked: 0.15,
			advancedSecurityNewRepos: 0.15,
			dependabotAlertsNewRepos: 0.2,
			secretScanningNewRepos:   0.15,
			pushProtectionNewRepos:   0.1,
			hasDescription:           0.25,
			hasTopics:                0.15,
			branchProtected:          0.1,
			dependabotAlertsEnabled:  0.15,
			securityPolicyExists:     0.1,
			codeOwnersExists:         0.1,
			deleteBranchOnMerge:      0.2,
			dependabotConfigExists:   0.15,
			hasIssuesOrDiscussions:   0.7,
			maxOpenAlerts:            40,
		}, nil
	default:
		return profileWeights{}, fmt.Errorf("unknown profile %q (expected clean|typical|noisy)", p)
	}
}

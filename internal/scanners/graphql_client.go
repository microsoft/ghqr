package scanners

import (
	"context"
	"net/http"

	"github.com/shurcooL/githubv4"
)

// GraphQLClient wraps the GitHub GraphQL API client.
// httpClient is the underlying HTTP client used by the githubv4 client;
// it is reused for batch queries that require raw HTTP POST requests.
type GraphQLClient struct {
	client     *githubv4.Client
	httpClient *http.Client
}

// NewGraphQLClient creates a new GraphQL client wrapper.
// httpClient should be the same HTTP client used to create the githubv4 client
// so that authentication and rate-limit retry logic are shared.
func NewGraphQLClient(client *githubv4.Client, httpClient *http.Client) *GraphQLClient {
	return &GraphQLClient{
		client:     client,
		httpClient: httpClient,
	}
}

// RepositoryNode holds all repository fields fetched from GitHub GraphQL.
// Used in single-repo queries (RepositoryCoreData).
type RepositoryNode struct {
	// Basic metadata
	Name        githubv4.String
	Description githubv4.String
	PushedAt    githubv4.String
	IsPrivate   githubv4.Boolean
	Visibility  githubv4.String
	IsFork      githubv4.Boolean
	IsArchived  githubv4.Boolean
	IsTemplate  githubv4.Boolean

	// Features
	HasIssuesEnabled      githubv4.Boolean
	HasProjectsEnabled    githubv4.Boolean
	HasWikiEnabled        githubv4.Boolean
	HasDiscussionsEnabled githubv4.Boolean

	// Primary language
	PrimaryLanguage struct {
		Name githubv4.String
	}

	// License
	LicenseInfo struct {
		Name   githubv4.String
		Key    githubv4.String
		SpdxId githubv4.String
	}

	// Topics
	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name githubv4.String
			}
		}
	} `graphql:"repositoryTopics(first: 50)"`

	// Default branch
	DefaultBranchRef struct {
		Name githubv4.String

		// Branch protection
		BranchProtectionRule struct {
			Pattern                      githubv4.String
			RequiredApprovingReviewCount githubv4.Int
			RequiresStrictStatusChecks   githubv4.Boolean
			RequiresStatusChecks         githubv4.Boolean
			RequiresCodeOwnerReviews     githubv4.Boolean
			RequiresCommitSignatures     githubv4.Boolean
			RequiresLinearHistory        githubv4.Boolean
			AllowsForcePushes            githubv4.Boolean
			AllowsDeletions              githubv4.Boolean
			DismissesStaleReviews        githubv4.Boolean

			RequiredStatusChecks []struct {
				Context githubv4.String
				// Note: AppID field doesn't exist in GitHub's GraphQL API
				// Use REST API if app information is needed
			}
		}
	}

	// Merge settings
	DeleteBranchOnMerge githubv4.Boolean

	// Security
	HasVulnerabilityAlertsEnabled githubv4.Boolean

	// Dependabot alerts
	VulnerabilityAlerts struct {
		Nodes []struct {
			DismissedAt           *githubv4.DateTime
			SecurityVulnerability struct {
				Severity githubv4.String
			}
		}
	} `graphql:"vulnerabilityAlerts(first: 100, states: OPEN)"`

	// Collaborators
	Collaborators struct {
		Edges []struct {
			Permission githubv4.String
			Node       struct {
				Login githubv4.String
			}
		}
	} `graphql:"collaborators(first: 100)"`

	// Deploy keys
	DeployKeys struct {
		Nodes []struct {
			Title    githubv4.String
			ReadOnly githubv4.Boolean
			Verified githubv4.Boolean
		}
	} `graphql:"deployKeys(first: 100)"`

	// Configuration files
	CodeownersFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"codeownersFile: object(expression: \"HEAD:CODEOWNERS\")"`

	GithubCodeownersFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"githubCodeownersFile: object(expression: \"HEAD:.github/CODEOWNERS\")"`

	DocsCodeownersFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"docsCodeownersFile: object(expression: \"HEAD:docs/CODEOWNERS\")"`

	SecurityMdFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"securityMdFile: object(expression: \"HEAD:SECURITY.md\")"`

	DependabotYmlFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"dependabotYmlFile: object(expression: \"HEAD:.github/dependabot.yml\")"`

	DependabotYamlFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"dependabotYamlFile: object(expression: \"HEAD:.github/dependabot.yaml\")"`

	CodeqlConfigFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"codeqlConfigFile: object(expression: \"HEAD:.github/codeql/config.yml\")"`

	CodeqlAltConfigFile struct {
		Blob struct {
			Oid githubv4.String
		} `graphql:"... on Blob"`
	} `graphql:"codeqlAltConfigFile: object(expression: \"HEAD:.github/codeql-config.yml\")"`
}

// orgRepoNamesQuery pages through org repository names only — kept lightweight
// to avoid GitHub's GraphQL resource-limit errors that occur when nesting full
// repository data inside an organization connection.
type orgRepoNamesQuery struct {
	Organization struct {
		Repositories struct {
			Nodes []struct {
				Name githubv4.String
			}
			PageInfo struct {
				HasNextPage githubv4.Boolean
				EndCursor   githubv4.String
			}
		} `graphql:"repositories(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC})"`
	} `graphql:"organization(login: $org)"`
}

// FetchOrgRepositoryNames pages through all repository names in an organization.
// Uses a lightweight query (names only) to avoid GraphQL resource-limit errors
// that arise from nesting deeply-nested repository data inside an org connection.
// Callers should follow up with FetchRepositoryCore for full data per repo.
func (c *GraphQLClient) FetchOrgRepositoryNames(ctx context.Context, org string) ([]string, error) {
	const reposPerPage = 100
	var names []string
	var cursor *githubv4.String
	for {
		var query orgRepoNamesQuery
		variables := map[string]interface{}{
			"org":   githubv4.String(org),
			"first": githubv4.Int(reposPerPage),
			"after": cursor,
		}
		if err := c.client.Query(ctx, &query, variables); err != nil {
			return nil, err
		}
		for _, node := range query.Organization.Repositories.Nodes {
			names = append(names, string(node.Name))
		}
		if !bool(query.Organization.Repositories.PageInfo.HasNextPage) {
			break
		}
		end := query.Organization.Repositories.PageInfo.EndCursor
		cursor = &end
	}
	return names, nil
}

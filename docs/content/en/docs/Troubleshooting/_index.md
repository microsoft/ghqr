---
title: Troubleshooting and Support
description: Troubleshooting and Support for GitHub Quick Review (ghqr)
weight: 6
---

If you encounter any issue while using **GitHub Quick Review (ghqr)**, run the command with the `--debug` flag to enable verbose logging:

```bash
ghqr scan -o my-org --debug
```

## Authentication Errors

If you receive `401 Unauthorized` or `403 Forbidden` errors:

1. Verify your `GITHUB_TOKEN` is set and valid.
2. Check that your token has the required scopes (see [Usage - Authentication](../usage/#authentication)).
3. For enterprise resources, ensure your token has `read:enterprise` scope and that SSO is authorized for the enterprise.
4. If using GitHub Enterprise Cloud with Data Residency (GHE.com), ensure you pass `--hostname` or set `GH_HOST` (see [Usage - GHE.com](../usage/#github-enterprise-cloud-with-data-residency-ghecom)).

## GHES Connection Errors

If ghqr cannot connect to your GitHub Enterprise Server instance:

1. Verify `GH_TOKEN` or `GITHUB_TOKEN` is set and was created on the GHES instance, not on github.com.
2. Ensure the hostname is correct and reachable from your network (e.g. `ghes.example.com`).
3. The token must have `site_admin` scope for full scanning capabilities.
4. If some checks show "not available", the token may lack sufficient permissions. Re-create the token with `site_admin` scope.
5. GHES instances behind a VPN or firewall require network access from the machine running ghqr.

## Rate Limiting

GitHub API has rate limits (5,000 requests/hour for REST, 5,000 points/hour for GraphQL). For large enterprises or organizations, ghqr handles rate limiting automatically with exponential backoff. If a scan is taking a long time, this is expected behavior for large environments.

## Unexpected or Missing Findings

- Ensure your token has all the required scopes listed in [Usage - Authentication](../usage/#authentication).
- Confirm the organization or enterprise slug is correct and that the token has been granted SSO access if your enterprise uses SAML.
- For repositories that show no findings, verify the token has `repo` scope (not just `public_repo`).

## Support

This project uses GitHub Issues to track bugs and feature requests. Before logging an issue, please check the troubleshooting steps above.

Please search the existing issues before filing new ones to avoid duplicates.

- For bugs and feature requests: [GitHub Issues](https://github.com/microsoft/ghqr/issues)
- For questions and discussion: [GitHub Discussions](https://github.com/microsoft/ghqr/discussions)

Support for this project is limited to the resources listed above.

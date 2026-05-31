---
title: Contribution Guidelines
weight: 5
description: How to contribute to the project
---

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Adding or Modifying Recommendations

Recommendations are stored as YAML files under `internal/recommendations/definitions/`. Each file maps to a scope (`repository`, `organization`, `enterprise`, `ghes`). To add a new recommendation:

1. Open the appropriate YAML file for the scope (e.g., `internal/recommendations/definitions/repository/security.yaml`).
2. Add a new entry following the existing schema:

   ```yaml
   - id: repo-sec-010
     scope: repository
     title: Short human-readable title
     category: security
     severity: high
     description: What the check evaluates and why it matters.
     recommendation: Actionable remediation guidance.
     learnMore: https://docs.github.com/...
     tags: [security]
     enabled: true
   ```

3. Implement the corresponding evaluation logic in `internal/scanners/bestpractices/`.
4. Add a unit test covering the positive (issue found) and negative (no issue) paths.
5. Run `make test` before submitting your pull request.

## Contributing to Documentation

The following packages are required to build and run the documentation site locally:

- `git`
- `hugo` (extended edition, version 0.110.0 or higher)
- `nodejs` (version 18 or higher)

### Running the Docs Site Locally

1. Fork the ghqr repository and clone it locally.

2. Navigate to the `docs` folder:

   ```bash
   cd ghqr/docs
   ```

3. Install Node modules:

   ```bash
   npm install
   ```

4. Start the Hugo development server:

   ```bash
   hugo server
   ```

5. Open your browser at `http://localhost:1313/ghqr/`.

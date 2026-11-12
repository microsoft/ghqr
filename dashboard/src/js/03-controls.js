/* ─── Controls: what "good" looks like, evaluated against the raw data ──── */
const STANDARD_BRANCHES = new Set(['main', 'master', 'develop', 'trunk']);

function defineControls(m) {
  const active = m.repos.filter((r) => !r.archived);
  const orgs = m.orgs.filter((o) => !o.stub);
  const ent = m.enterprise ? [m.enterprise] : [];
  const budgets = m.enterprise?.budgets || [];
  const orgW = (o) => Math.max(1, o.activeRepoCount);
  const alertTest = (k) => (o) => (o.alerts.available && o.alerts[k] != null ? o.alerts[k] === 0 : null);
  const ruleLink = (id, fallback) => m.findings.find((f) => f.ruleId === id && f.learnMore)?.learnMore || fallback;

  const list = [
    /* Vulnerability management */
    { id: 'vuln-critical', domain: 'vuln', scope: 'org', severity: 'critical', ghqr: 'org-alert-001 · ent-alert-001', alertKey: 'critical',
      entities: orgs, test: alertTest('critical'), weightBy: orgW,
      title: 'No open critical Dependabot alerts', fix: 'Burn down critical Dependabot alerts',
      why: 'Critical dependency vulnerabilities are publicly known and actively exploited — the fastest route into an application.',
      action: 'Remediate every critical Dependabot alert now and agree a short remediation SLA (for example 7 days) for new ones.',
      scale: 'Work from Security overview filtered by severity and assign each alert an owner. Where appropriate, enable Dependabot security updates through a code security configuration so fixes arrive as ready-to-merge pull requests.',
      effort: 'M', owner: 'Security + repository owners', learn: ruleLink('org-alert-001', DOCS.dependabot) },
    { id: 'vuln-high', domain: 'vuln', scope: 'org', severity: 'high', ghqr: 'org-alert-002 · ent-alert-002', alertKey: 'high',
      entities: orgs, test: alertTest('high'), weightBy: orgW,
      title: 'No open high-severity Dependabot alerts', fix: 'Burn down high-severity Dependabot alerts',
      why: 'High-severity dependency flaws are a common supply-chain entry point and accumulate quickly in active repositories.',
      action: 'Clear high-severity alerts after the criticals, with a 30-day remediation SLA.',
      scale: 'Group fixes by package — a single upgrade often closes the same alert in many repositories. Track burn-down per organisation in Security overview.',
      effort: 'M', owner: 'Security + repository owners', learn: ruleLink('org-alert-002', DOCS.dependabot) },
    { id: 'vuln-code', domain: 'vuln', scope: 'org', severity: 'high', ghqr: 'org-alert-004 · ent-alert-003', alertKey: 'codeScanning',
      entities: orgs, test: alertTest('codeScanning'), weightBy: orgW,
      title: 'No open code scanning alerts', fix: 'Triage and fix open code scanning alerts',
      why: 'Code scanning alerts flag potential vulnerabilities in first-party code, such as injection flaws and unsafe data handling.',
      action: 'Triage every open alert: fix it, or dismiss it with a documented reason (false positive, used in tests, won’t fix).',
      scale: 'Start with the organisation holding the largest backlog, then keep it at zero by surfacing code scanning results on every pull request.',
      effort: 'M', owner: 'Security + repository owners', learn: ruleLink('org-alert-004', DOCS.codeScanning) },
    { id: 'vuln-secret', domain: 'vuln', scope: 'org', severity: 'critical', ghqr: '', alertKey: 'secretScanning',
      entities: orgs, test: alertTest('secretScanning'), weightBy: orgW,
      title: 'No open secret scanning alerts', fix: 'Revoke and rotate exposed secrets',
      why: 'A leaked credential gives an attacker direct access — no exploit required.',
      action: 'Revoke and rotate any exposed secret immediately, then close the alert.',
      scale: 'Keep push protection on everywhere and configure bypass reviewers so exceptions are approved.',
      note: 'A zero count is only meaningful if secret scanning covers every repository — confirm coverage in Security overview.',
      effort: 'S', owner: 'Security', learn: DOCS.secretScanning },
    { id: 'vuln-dependabot', domain: 'vuln', scope: 'repo', severity: 'high', ghqr: 'repo-sec-001',
      entities: active, test: (r) => r.dependabotAlerts,
      title: 'Dependabot alerts enabled', fix: 'Enable Dependabot alerts everywhere',
      why: 'Without Dependabot alerts, vulnerable dependencies go unnoticed.',
      action: 'Enable the dependency graph and Dependabot alerts on every active repository.',
      scale: 'Apply a code security configuration at organisation or enterprise level and make it the default for new repositories.',
      effort: 'S', owner: 'Platform / security', learn: DOCS.atScale },
    { id: 'vuln-updates', domain: 'vuln', scope: 'repo', severity: 'medium', ghqr: '',
      entities: active, test: (r) => r.dependabotConfig,
      title: 'Dependabot version updates configured', fix: 'Add dependabot.yml for version updates',
      why: 'Keeping dependencies current shrinks tomorrow’s vulnerability backlog and keeps security fixes small and easy to merge.',
      action: 'Add .github/dependabot.yml covering every package ecosystem in the repository.',
      scale: 'Seed dependabot.yml from repository templates or configuration-as-code automation; use grouped updates to limit pull-request noise.',
      effort: 'S', owner: 'Repository owners', learn: DOCS.versionUpdates },

    /* Branch protection & review */
    { id: 'bp-protected', domain: 'branch', scope: 'repo', severity: 'high', ghqr: '',
      entities: active, test: (r) => r.isProtected,
      title: 'Default branch protected', fix: 'Protect every default branch',
      why: 'An unprotected default branch accepts direct pushes that bypass review and CI.',
      action: 'Protect every default branch with a ruleset.',
      scale: 'Use organisation rulesets that target the default branch of every repository.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.rulesets },
    { id: 'bp-force', domain: 'branch', scope: 'repo', severity: 'high', ghqr: '',
      entities: active, test: (r) => r.forcePushBlocked,
      title: 'Force pushes blocked', fix: 'Block force pushes on default branches',
      why: 'Force pushes can rewrite or erase history on the mainline.',
      action: 'Enable “Block force pushes” in the default-branch ruleset.',
      scale: 'Include the rule in the organisation-wide default-branch ruleset.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.rules },
    { id: 'bp-delete', domain: 'branch', scope: 'repo', severity: 'medium', ghqr: '',
      entities: active, test: (r) => r.deletionBlocked,
      title: 'Default branch deletion blocked', fix: 'Restrict default-branch deletion',
      why: 'Deleting the default branch disrupts delivery and can destroy unmerged work.',
      action: 'Enable “Restrict deletions” in the default-branch ruleset.',
      scale: 'Include the rule in the organisation-wide default-branch ruleset.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.rules },
    { id: 'bp-review', domain: 'branch', scope: 'repo', severity: 'high', ghqr: '',
      entities: active, test: (r) => r.approvals >= 1,
      title: 'Pull request with approval required', fix: 'Require reviewed pull requests',
      why: 'Peer review is the primary control against unreviewed or malicious changes.',
      action: 'Require a pull request with at least one approval before merging.',
      scale: 'Set the rule once in an organisation ruleset rather than per repository.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.rules },
    { id: 'bp-stale', domain: 'branch', scope: 'repo', severity: 'medium', ghqr: '',
      entities: active, test: (r) => r.approvals >= 1 && r.dismissStale,
      title: 'Stale approvals dismissed on new commits', fix: 'Dismiss stale approvals',
      why: 'Otherwise, code pushed after an approval can merge without being reviewed.',
      action: 'Enable “Dismiss stale pull request approvals when new commits are pushed”.',
      scale: 'Set the option on the organisation ruleset’s pull-request rule.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.rules },
    { id: 'bp-checks', domain: 'branch', scope: 'repo', severity: 'high', ghqr: 'repo-bp-009 · repo-bp-007',
      entities: active, test: (r) => r.statusChecks && r.strictChecks,
      detail: (r) => (r.statusChecks ? `${r.contexts.length} check(s), not strict` : 'no required checks'),
      title: 'Required status checks (up to date)', fix: 'Enforce required CI status checks',
      why: 'Without required checks, pull requests can merge even when builds, tests or security scans fail.',
      action: 'Require CI status checks to pass, and require branches to be up to date before merging.',
      scale: 'Add a “Require status checks to pass” rule to organisation rulesets — or, where available, “Require workflows to pass before merging” to enforce a central gate workflow. Pilot in Evaluate mode, then switch to Active.',
      effort: 'S', owner: 'Platform / DevOps', learn: ruleLink('repo-bp-009', DOCS.protectedBranches) },
    { id: 'bp-two', domain: 'branch', scope: 'repo', severity: 'medium', ghqr: 'repo-bp-003',
      entities: active, test: (r) => r.approvals >= 2, detail: (r) => `${r.approvals} approval(s) required`,
      title: 'Two or more approvals required', fix: 'Require two approvals on production code',
      why: 'A second reviewer materially reduces the chance of a defect or malicious change reaching production.',
      action: 'Require at least two approving reviews on production branches.',
      scale: 'Target production repositories first (for example by custom property in organisation rulesets), then widen.',
      effort: 'S', owner: 'Platform / DevOps', learn: ruleLink('repo-bp-003', DOCS.protectedBranches) },
    { id: 'bp-signed', domain: 'branch', scope: 'repo', severity: 'medium', ghqr: 'repo-bp-012',
      entities: active, test: (r) => r.signed,
      title: 'Signed commits required', fix: 'Require signed commits',
      why: 'Commit signatures prove who authored a change and that it was not tampered with.',
      action: 'Enable “Require signed commits” on default branches.',
      scale: 'Help developers set up SSH or GPG commit signing first, then roll the rule out through organisation rulesets — pilot in Evaluate mode.',
      effort: 'M', owner: 'Platform / DevOps', learn: ruleLink('repo-bp-012', DOCS.protectedBranches) },
    { id: 'bp-linear', domain: 'branch', scope: 'repo', severity: 'low', ghqr: 'repo-bp-013',
      entities: active, test: (r) => r.linear,
      title: 'Linear history required', fix: 'Require linear history',
      why: 'Linear history makes audits, bisecting and reverts simpler.',
      action: 'Enable “Require linear history” (squash or rebase merges).',
      scale: 'Add the rule to organisation rulesets alongside the merge-method policy.',
      effort: 'S', owner: 'Platform / DevOps', learn: ruleLink('repo-bp-013', DOCS.protectedBranches) },
    { id: 'bp-codeowners', domain: 'branch', scope: 'repo', severity: 'medium', ghqr: 'repo-sec-005',
      entities: active, test: (r) => r.codeowners,
      detail: (r) => (r.codeOwnerReviews ? 'code-owner review required, but no owners defined' : 'no CODEOWNERS file'),
      title: 'CODEOWNERS file present', fix: 'Add CODEOWNERS files',
      why: 'CODEOWNERS routes changes to accountable reviewers. Where rulesets require code-owner review, a missing CODEOWNERS file means the requirement never triggers.',
      action: 'Add .github/CODEOWNERS mapping paths to the owning teams.',
      scale: 'Generate CODEOWNERS from team-ownership data through configuration-as-code or repository templates.',
      effort: 'S', owner: 'Repository owners', learn: ruleLink('repo-sec-005', DOCS.codeowners) },
    { id: 'bp-signoff', domain: 'branch', scope: 'org', severity: 'low', ghqr: '',
      entities: orgs, test: (o) => o.webSignoff,
      title: 'Web commit sign-off required', fix: 'Require sign-off on web commits',
      why: 'Sign-off records contributor attestation for changes made in the browser.',
      action: 'Enable “Require contributors to sign off on web-based commits”.',
      scale: 'Set it in every organisation’s repository settings.',
      effort: 'S', owner: 'Organisation owners', learn: DOCS.signoff },

    /* Identity & access */
    { id: 'id-emu', domain: 'identity', scope: 'enterprise', severity: 'high', ghqr: '',
      entities: ent, test: (e) => e.emu,
      title: 'Enterprise Managed Users', fix: 'Adopt Enterprise Managed Users',
      why: 'Managed identities keep account lifecycle, MFA and access under the control of your identity provider.',
      action: 'Use Enterprise Managed Users with SCIM provisioning from your identity provider.',
      scale: 'Requires a new EMU enterprise and migration planning.',
      effort: 'L', owner: 'Identity team', learn: DOCS.emu },
    { id: 'id-public-create', domain: 'identity', scope: 'org', severity: 'high', ghqr: '',
      entities: orgs, test: (o) => (o.publicCreation == null ? null : o.publicCreation === false),
      title: 'Members cannot create public repositories', fix: 'Block public repository creation',
      why: 'Prevents accidental publication of internal source code.',
      action: 'Disable public repository creation for members.',
      scale: 'Enforce the repository-creation policy at enterprise level.',
      effort: 'S', owner: 'Organisation owners', learn: DOCS.repoCreation },
    { id: 'id-no-public', domain: 'identity', scope: 'repo', severity: 'high', ghqr: '', allRepos: true,
      entities: m.repos, test: (r) => r.visibility !== 'PUBLIC',
      title: 'No public repositories', fix: 'Make public repositories internal or private',
      why: 'Public repositories expose source code, history and configuration to the internet.',
      action: 'Review each public repository and change its visibility unless publication is intended and approved.',
      scale: 'Restrict repository visibility changes to organisation owners.',
      effort: 'S', owner: 'Organisation owners', learn: DOCS.repoCreation },
    { id: 'id-secmgr', domain: 'identity', scope: 'org', severity: 'medium', ghqr: '',
      entities: orgs, test: (o) => o.securityManager,
      title: 'Security manager role assigned', fix: 'Assign the security manager role',
      why: 'A security manager team can see and manage security alerts across every repository in the organisation.',
      action: 'Assign the security manager role to your security team in every organisation.',
      scale: 'Include the assignment in organisation bootstrap automation.',
      effort: 'S', owner: 'Organisation owners', learn: DOCS.securityManagers },
    { id: 'id-base', domain: 'identity', scope: 'org', severity: 'high', ghqr: '',
      entities: orgs, test: (o) => (o.basePermission == null ? null : ['read', 'none'].includes(String(o.basePermission).toLowerCase())),
      detail: (o) => `base permission “${o.basePermission}”`,
      title: 'Least-privilege base permission', fix: 'Lower the base permission to read (or none)',
      why: 'The base permission applies to every member on every repository in the organisation. “Write” lets any member push branches anywhere and — with single-approval reviews and no code owners — lets two members land a change on almost any default branch.',
      action: 'Set the base permission to “Read” (or “No permission”) and grant write access through teams.',
      scale: 'Map teams to repositories first (for example through configuration-as-code), then lower the base permission organisation by organisation.',
      effort: 'M', owner: 'Organisation owners', learn: DOCS.basePermissions },

    /* Actions & CI/CD */
    { id: 'act-allowed', domain: 'actions', scope: 'org', severity: 'high', ghqr: '',
      entities: orgs, test: (o) => (o.allowedActions == null ? null : o.allowedActions !== 'all'),
      detail: (o) => `allowed actions “${o.allowedActions}”`,
      title: 'Allowed actions restricted', fix: 'Restrict which actions can run',
      why: 'Unrestricted third-party actions run with access to your code, secrets and tokens.',
      action: 'Allow only selected actions — for example GitHub-authored, verified creators and an approved list.',
      scale: 'Set the policy at enterprise level so every organisation inherits it.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.actionsPolicy },
    { id: 'act-token', domain: 'actions', scope: 'org', severity: 'high', ghqr: '',
      entities: orgs, test: (o) => (o.tokenPerm == null ? null : o.tokenPerm === 'read'),
      title: 'Workflow token read-only by default', fix: 'Make GITHUB_TOKEN read-only by default',
      why: 'A read-only default GITHUB_TOKEN limits the blast radius of a compromised workflow; jobs request extra permissions explicitly.',
      action: 'Set default workflow permissions to read repository contents and packages.',
      scale: 'Set the default at enterprise level so every organisation inherits it.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.token },
    { id: 'act-approve', domain: 'actions', scope: 'org', severity: 'high', ghqr: '',
      entities: orgs, test: (o) => (o.actionsCanApprove == null ? null : o.actionsCanApprove === false),
      title: 'Workflows cannot approve pull requests', fix: 'Stop workflows approving pull requests',
      why: 'If workflows can approve pull requests, automation can satisfy review requirements without a human.',
      action: 'Disable “Allow GitHub Actions to create and approve pull requests”.',
      scale: 'Set it at enterprise level so every organisation inherits it.',
      effort: 'S', owner: 'Platform / DevOps', learn: DOCS.actionsPolicy },

    /* Repository hygiene */
    { id: 'hy-desc', domain: 'hygiene', scope: 'repo', severity: 'medium', ghqr: 'repo-meta-001',
      entities: active, test: (r) => !!r.description,
      title: 'Repository description', fix: 'Add repository descriptions',
      why: 'Descriptions make repositories discoverable and help new engineers understand purpose and ownership quickly.',
      action: 'Add a one-line description to every repository.',
      scale: 'Bulk-update through the REST API or configuration-as-code.',
      effort: 'S', owner: 'Repository owners', learn: ruleLink('repo-meta-001', DOCS.metadata) },
    { id: 'hy-topics', domain: 'hygiene', scope: 'repo', severity: 'low', ghqr: 'repo-meta-002',
      entities: active, test: (r) => r.topics.length > 0,
      title: 'Repository topics', fix: 'Tag repositories with topics',
      why: 'Topics improve search and let teams find related work.',
      action: 'Add topics for product, platform and technology.',
      scale: 'For governance targeting prefer custom properties; use topics for discovery.',
      effort: 'S', owner: 'Repository owners', learn: ruleLink('repo-meta-002', DOCS.topics) },
    { id: 'hy-secpolicy', domain: 'hygiene', scope: 'repo', severity: 'low', ghqr: 'repo-sec-004',
      entities: active, test: (r) => r.securityMd,
      title: 'SECURITY.md policy', fix: 'Publish a security policy',
      why: 'Tells engineers how to report a vulnerability and who responds.',
      action: 'Add a SECURITY.md describing how to report vulnerabilities.',
      scale: 'Ship a standard SECURITY.md in repository templates and backfill existing repositories automatically.',
      effort: 'S', owner: 'Security team', learn: ruleLink('repo-sec-004', DOCS.securityPolicy) },
    { id: 'hy-branch', domain: 'hygiene', scope: 'repo', severity: 'low', ghqr: '',
      entities: active, test: (r) => (r.defaultBranch ? STANDARD_BRANCHES.has(r.defaultBranch) : null),
      detail: (r) => `default branch “${r.defaultBranch}”`,
      title: 'Conventional default branch', fix: 'Reset feature or snapshot default branches',
      why: 'When a feature or snapshot branch is the default, default-branch rulesets protect it instead of the intended mainline, and new pull requests target it.',
      action: 'Switch the default branch back to main (or your standard) and retire temporary branches.',
      scale: 'Detect non-standard defaults in configuration-as-code and report them to owners.',
      effort: 'S', owner: 'Repository owners', learn: DOCS.defaultBranch },
    { id: 'hy-autodelete', domain: 'hygiene', scope: 'repo', severity: 'low', ghqr: 'repo-feat-002',
      entities: active, test: (r) => r.deleteBranchOnMerge,
      title: 'Merged branches auto-deleted', fix: 'Auto-delete merged branches',
      why: 'Stale branches clutter repositories and can hold outdated, vulnerable code.',
      action: 'Enable “Automatically delete head branches”.',
      scale: 'Apply as a repository default through configuration-as-code.',
      effort: 'S', owner: 'Repository owners', learn: ruleLink('repo-feat-002', DOCS.autoDelete) },
    { id: 'hy-issues', domain: 'hygiene', scope: 'repo', severity: 'low', ghqr: 'repo-feat-001',
      entities: active, test: (r) => r.hasIssues || r.hasDiscussions,
      title: 'Issues or Discussions enabled', fix: 'Enable Issues or Discussions',
      why: 'Gives users a structured channel for bugs and feedback.',
      action: 'Enable Issues (or Discussions) unless the repository is intentionally closed to feedback.',
      scale: 'Document intentional exceptions (for example gate or mirror repositories).',
      effort: 'S', owner: 'Repository owners', learn: ruleLink('repo-feat-001', DOCS.discussions) },

    /* Copilot & cost governance */
    { id: 'gov-public-code', domain: 'governance', scope: 'org', severity: 'medium', ghqr: '',
      entities: orgs.filter((o) => o.copilot), test: (o) => (o.copilot?.publicCode ? o.copilot.publicCode === 'block' : null),
      title: 'Copilot public-code matches blocked', fix: 'Block Copilot suggestions matching public code',
      why: 'Blocking suggestions that match public code reduces licence and IP compliance risk.',
      action: 'Set “Suggestions matching public code” to Blocked.',
      scale: 'Set the policy at enterprise level so every organisation inherits it.',
      effort: 'S', owner: 'Platform / AI governance', learn: DOCS.copilotPolicies },
    { id: 'gov-budgets', domain: 'governance', scope: 'enterprise', severity: 'medium', ghqr: '',
      entities: m.enterprise?.budgetsAvailable ? ent : [], test: (e) => e.budgets.length > 0,
      title: 'Enterprise budgets configured', fix: 'Create enterprise budgets',
      why: 'Budgets make metered spend (for example Actions, Codespaces and Copilot) visible and controllable.',
      action: 'Create budgets for the enterprise and key cost centres.',
      scale: 'Review budgets quarterly with finance.',
      effort: 'S', owner: 'Enterprise owners + finance', learn: DOCS.budgets },
    { id: 'gov-cap', domain: 'governance', scope: 'budget', severity: 'medium', ghqr: 'ent-budget-003',
      entities: budgets, test: (b) => b.prevent,
      title: 'Budgets stop usage at the limit', fix: 'Enable “prevent further usage” where hard caps are needed',
      why: 'Without a hard stop, spend continues past the budget.',
      action: 'Enable “prevent further usage” on budgets that must act as hard caps; keep alerting on advisory budgets.',
      scale: 'Agree which budgets are hard caps and which are advisory, and document it.',
      effort: 'S', owner: 'Enterprise owners + finance', learn: ruleLink('ent-budget-003', DOCS.budgets) },
    { id: 'gov-alert', domain: 'governance', scope: 'budget', severity: 'low', ghqr: '',
      entities: budgets, test: (b) => b.alerting,
      title: 'Budgets send alerts', fix: 'Add alert recipients to every budget',
      why: 'Alerts give finance and platform owners early warning before a limit is reached.',
      action: 'Enable budget alerts with named recipients on every budget.',
      scale: 'Use a shared mailbox or distribution list rather than an individual.',
      effort: 'S', owner: 'Enterprise owners + finance', learn: DOCS.budgets },
  ];

  return list.map((c) => evaluateControl(c, m));
}

function evaluateControl(c, m) {
  const known = [], pass = [], fail = [];
  for (const e of c.entities) {
    const t = c.test(e);
    if (t == null) continue;
    known.push(e);
    (t ? pass : fail).push(e);
  }
  const w = c.weightBy || (() => 1);
  const tw = sum(known, w);
  c.known = known;
  c.pass = pass;
  c.fail = fail;
  c.knownSet = new Set(known);
  c.passSet = new Set(pass);
  c.rate = tw > 0 ? sum(pass, w) / tw : null;
  c.weight = SEV_WEIGHT[c.severity];
  c.ghqrIds = c.ghqr ? c.ghqr.split(' · ') : [];
  c.source = c.ghqr ? `GHQR ${c.ghqr}` : 'Derived from GHQR raw data';
  c.related = m.findings.filter((f) => c.ghqrIds.includes(f.ruleId));
  c.relatedArchived = c.related.filter((f) => f.scope === 'repo' && m.repoMap.get(f.entity)?.archived);
  const unit = c.scope === 'repo' ? (c.allRepos ? ['repository', 'repositories'] : ['active repository', 'active repositories'])
    : c.scope === 'org' ? ['organisation', 'organisations'] : c.scope === 'budget' ? ['budget', 'budgets'] : ['enterprise', 'enterprises'];
  c.unit = unit;
  c.phase = c.severity === 'critical' || c.severity === 'high' ? 'now' : c.severity === 'medium' ? 'next' : 'later';
  c.gap = GAPS[c.id] || c.fix.toLowerCase();
  return c;
}

const entityName = (scope, e) => (scope === 'repo' ? e.full : scope === 'org' ? e.login : scope === 'enterprise' ? e.slug : `${e.scope} · ${e.entity || '—'}`);

/* Short noun phrases describing each gap, used in narrative text. */
const GAPS = {
  'vuln-critical': 'open critical Dependabot alerts', 'vuln-high': 'open high-severity Dependabot alerts',
  'vuln-code': 'open code scanning alerts', 'vuln-secret': 'open secret scanning alerts',
  'vuln-dependabot': 'repositories without Dependabot alerts', 'vuln-updates': 'missing Dependabot version updates',
  'bp-protected': 'unprotected default branches', 'bp-force': 'force pushes allowed', 'bp-delete': 'default-branch deletion allowed',
  'bp-review': 'merges without review', 'bp-stale': 'stale approvals kept', 'bp-checks': 'missing required CI checks',
  'bp-two': 'single-approver reviews', 'bp-signed': 'unsigned commits', 'bp-linear': 'non-linear history',
  'bp-codeowners': 'missing CODEOWNERS files', 'bp-signoff': 'no web commit sign-off',
  'id-emu': 'unmanaged identities', 'id-public-create': 'public repository creation allowed', 'id-no-public': 'public repositories',
  'id-secmgr': 'no security manager', 'id-base': 'broad base permissions',
  'act-allowed': 'unrestricted actions', 'act-token': 'write-by-default workflow tokens', 'act-approve': 'workflows able to approve pull requests',
  'hy-desc': 'missing descriptions', 'hy-topics': 'untagged repositories', 'hy-secpolicy': 'missing security policies',
  'hy-branch': 'non-standard default branches', 'hy-autodelete': 'merged branches left behind', 'hy-issues': 'no feedback channel',
  'gov-public-code': 'public-code matches allowed', 'gov-budgets': 'no budgets', 'gov-cap': 'budgets without hard caps', 'gov-alert': 'budgets without alerts',
};

function failPhrase(c) {
  if (c.rate == null) return 'Not assessed';
  if (c.alertKey) {
    const total = sum(c.fail, (o) => o.alerts[c.alertKey] || 0);
    const capped = c.fail.some((o) => o.alerts[c.alertKey] === 100);
    return c.fail.length ? `${fmtInt(total)}${capped ? '+' : ''} open in ${listText(c.fail.map((o) => o.login))}` : 'None open';
  }
  if (c.scope === 'enterprise') return c.fail.length ? 'Not in place for the enterprise' : 'In place';
  return `${fmtInt(c.fail.length)} of ${plural(c.known.length, c.unit[0], c.unit[1])}`;
}

function passPhrase(c) {
  if (c.scope === 'enterprise') return 'In place for the enterprise';
  if (c.alertKey) return `All ${plural(c.known.length, 'organisation')} at zero`;
  return c.pass.length === c.known.length ? `All ${plural(c.known.length, c.unit[0], c.unit[1])}` : `${fmtInt(c.pass.length)} of ${plural(c.known.length, c.unit[0], c.unit[1])}`;
}

/* ─── Scoring ─────────────────────────────────────────────────────────── */
function scoreControls(controls, fixed) {
  let tw = 0, ts = 0;
  for (const c of controls) {
    if (c.rate == null || !c.weight) continue;
    tw += c.weight;
    ts += c.weight * (fixed && fixed.has(c.id) ? 1 : c.rate);
  }
  return tw ? (100 * ts) / tw : null;
}

function entityScore(controls, scope, entity) {
  let tw = 0, ts = 0;
  const results = [];
  for (const c of controls) {
    if (c.scope !== scope || !c.knownSet.has(entity) || !c.weight) continue;
    const ok = c.passSet.has(entity);
    tw += c.weight;
    ts += ok ? c.weight : 0;
    results.push({ c, ok });
  }
  return { score: tw ? (100 * ts) / tw : null, results };
}

function orgScore(controls, org) {
  let tw = 0, ts = 0;
  for (const c of controls) {
    if (!c.weight) continue;
    let ents = [];
    if (c.scope === 'repo') ents = c.known.filter((r) => r.org === org.login);
    else if (c.scope === 'org' && c.knownSet.has(org)) ents = [org];
    if (!ents.length) continue;
    tw += c.weight;
    ts += (c.weight * ents.filter((e) => c.passSet.has(e)).length) / ents.length;
  }
  return tw ? (100 * ts) / tw : null;
}

/* ─── Analysis entry point ────────────────────────────────────────────── */
function analyse(raw, sourceName) {
  const m = buildModel(raw, sourceName);
  m.controls = defineControls(m);
  m.controlMap = new Map(m.controls.map((c) => [c.id, c]));
  m.scored = m.controls.filter((c) => c.rate != null && c.weight > 0);
  m.overall = scoreControls(m.scored);
  m.domains = DOMAINS.map((d) => {
    const cs = m.controls.filter((c) => c.domain === d.id);
    return { ...d, controls: cs, score: scoreControls(cs) };
  });
  m.domainMap = new Map(m.domains.map((d) => [d.id, d]));
  for (const c of m.controls) {
    c.uplift = c.rate != null && c.rate < 0.9995 && c.weight ? scoreControls(m.scored, new Set([c.id])) - m.overall : 0;
  }
  for (const r of m.repos) {
    const s = entityScore(m.controls, 'repo', r);
    r.score = r.archived ? null : s.score;
    r.results = s.results;
    r.failing = s.results.filter((x) => !x.ok).map((x) => x.c);
  }
  for (const o of m.orgs) o.score = orgScore(m.controls, o);
  m.groups = groupFindings(m);
  m.sev = countBySeverity(m.findings);
  m.focus = m.controls.filter((c) => c.uplift > 0.05).sort((a, b) => b.uplift - a.uplift);
  m.strengths = m.controls.filter((c) => c.rate != null && c.rate >= 0.9995 && c.weight)
    .sort((a, b) => b.weight - a.weight || b.known.length - a.known.length);
  m.insights = buildInsights(m);
  m.caveats = buildCaveats(m);
  return m;
}

/* ─── Derived insights (not GHQR rules — observations from the raw data) ── */
function buildInsights(m) {
  const out = [];
  const active = m.repos.filter((r) => !r.archived);
  const orgs = m.orgs.filter((o) => !o.stub);

  const coReq = active.filter((r) => r.codeOwnerReviews);
  const coGap = coReq.filter((r) => !r.codeowners);
  if (coGap.length) {
    out.push({ tone: 'warn', icon: 'users', control: 'bp-codeowners', title: 'Code-owner review is switched on — but there are no owners to enforce it',
      text: `${fmtInt(coReq.length)} active repositories require code-owner review in their rulesets, yet ${fmtInt(coGap.length)} have no CODEOWNERS file. The rule never triggers there, so a single approval from any writer is enough.` });
  }
  const permissive = orgs.filter((o) => ['write', 'admin', 'maintain'].includes(String(o.basePermission).toLowerCase()));
  if (permissive.length) {
    const perm = permissive[0].basePermission;
    out.push({ tone: 'warn', icon: 'key', control: 'id-base', title: `Every member gets “${perm}” access to every repository`,
      text: `${permissive.length === orgs.length ? 'All' : fmtInt(permissive.length) + ' of'} ${plural(orgs.length, 'organisation')} set the base permission to “${perm}”. Any member can push branches anywhere; combined with single-approval reviews, two members can land a change on almost any default branch.` });
  }
  const prot = active.filter((r) => r.isProtected);
  const noChecks = prot.filter((r) => !r.statusChecks);
  if (prot.length && noChecks.length / prot.length > 0.5) {
    const byName = {};
    for (const r of m.repos) (byName[r.name] ||= new Set()).add(r.org);
    const shared = Object.entries(byName).filter(([, s]) => s.size >= Math.max(3, Math.ceil(orgs.length / 2))).map(([n]) => n);
    const gate = shared.find((n) => /gate|check|scan|security/i.test(n));
    out.push({ tone: 'bad', icon: 'flow', control: 'bp-checks', title: 'Merges are reviewed, but not verified',
      text: `${fmtInt(noChecks.length)} of ${fmtInt(prot.length)} protected repositories require a review but no passing CI checks — builds, tests and scans are advisory.${gate ? ` A “${gate}” repository exists in ${fmtInt(byName[gate].size)} organisations; if it is meant to be a mandatory gate, enforce it through ruleset status checks or required workflows.` : ''}` });
  }
  const depOff = m.repos.filter((r) => !r.dependabotAlerts);
  if (depOff.length && depOff.every((r) => r.archived)) {
    out.push({ tone: 'info', icon: 'info', control: 'vuln-dependabot', title: 'Every “Dependabot alerts not enabled” finding is an archived repository',
      text: `All ${fmtInt(depOff.length)} of these high-severity GHQR findings relate to archived, read-only repositories — low day-to-day risk. Confirm the archive is intentional, or retire repositories that are no longer needed. Every active repository already has Dependabot alerts.` });
  }
  const odd = active.filter((r) => r.defaultBranch && !STANDARD_BRANCHES.has(r.defaultBranch));
  if (odd.length) {
    out.push({ tone: 'warn', icon: 'branch', control: 'hy-branch', title: `${fmtInt(odd.length)} repositories use a feature or snapshot branch as their default`,
      text: `For example ${odd.slice(0, 3).map((r) => `${r.name} → ${r.defaultBranch}`).join('; ')}. Default-branch rulesets then protect that branch instead of the intended mainline, and new pull requests target it.` });
  }
  const recent30 = m.repos.filter((r) => r.daysSincePush != null && r.daysSincePush <= 30).length;
  if (m.repos.length && recent30 / m.repos.length >= 0.6) {
    const created = m.enterprise?.createdAt;
    const months = created ? Math.max(1, Math.round((m.now - created) / (30.4 * 86400000))) : null;
    out.push({ tone: 'good', icon: 'trend', title: 'A young, fast-moving estate — the ideal moment for guardrails',
      text: `${fmtPct(recent30 / m.repos.length)} of repositories were pushed in the last 30 days${months ? ` and the enterprise is only about ${plural(months, 'month')} old` : ''}. Guardrails set now scale with the estate instead of being retrofitted later.` });
  }
  const top = active.filter((r) => r.score != null && r.score >= 80).sort((a, b) => b.score - a.score).slice(0, 3);
  if (top.length) {
    out.push({ tone: 'good', icon: 'sparkles', title: 'Internal exemplars already exist',
      text: `${listText(top.map((r) => `${r.full} (${fmtScore(r.score)})`))} ${top.length > 1 ? 'meet' : 'meets'} most controls — use them as reference implementations for other teams.`, repos: top.map((r) => r.full) });
  }
  const depOrgs = orgs.filter((o) => (o.alerts.dependabot || 0) > 0).sort((a, b) => b.alerts.dependabot - a.alerts.dependabot);
  const depTotal = sum(depOrgs, (o) => o.alerts.dependabot);
  if (depOrgs.length && depTotal && depOrgs[0].alerts.dependabot / depTotal >= 0.5) {
    out.push({ tone: 'bad', icon: 'bug', control: 'vuln-critical', title: `Vulnerability risk is concentrated in ${depOrgs[0].login}`,
      text: `${depOrgs[0].login} holds ${fmtPct(depOrgs[0].alerts.dependabot / depTotal)} of open Dependabot alerts (${fmtInt(depOrgs[0].alerts.dependabot)} of ${fmtInt(depTotal)}), including ${fmtInt(depOrgs[0].alerts.critical || 0)} critical. A focused remediation sprint there moves the whole estate.` });
  }
  const cp = orgs.filter((o) => o.copilot);
  const seats = sum(cp, (o) => o.copilot.seats || 0);
  if (cp.length && seats <= cp.length) {
    out.push({ tone: 'info', icon: 'copilot', title: 'Copilot is configured, but barely adopted',
      text: `Copilot billing is enabled in ${plural(cp.filter((o) => o.copilot.billing).length, 'organisation')}, yet only ${plural(seats, 'seat')} ${seats === 1 ? 'is' : 'are'} assigned across the enterprise (${fmtInt(sum(cp, (o) => o.copilot.active || 0))} active this cycle).` });
  }
  return out;
}

/* ─── Data-quality notes detected from the report itself ───────────────── */
function buildCaveats(m) {
  const out = [];
  const A = m.alerts;
  const capped = ['dependabot', 'codeScanning', 'critical', 'high'].filter((k) => A[k].entVal != null && A[k].orgSum != null && A[k].entVal < A[k].orgSum);
  if (capped.length) {
    out.push(`Enterprise-level alert figures are lower than the sum of organisation figures (for example Dependabot ${fmtInt(A.dependabot.entVal)} vs ${fmtInt(A.dependabot.orgSum)}); they appear to come from a capped sample of 100 alerts. This dashboard uses the higher organisation-level sums.`);
  }
  for (const k of ['dependabot', 'codeScanning']) {
    if (A[k].cappedOrgs.length) out.push(`${listText(A[k].cappedOrgs)} report${A[k].cappedOrgs.length === 1 ? 's' : ''} exactly 100 open ${k === 'codeScanning' ? 'code scanning' : 'Dependabot'} alerts — likely a collection page limit, so the true number may be higher (shown as “100+”).`);
  }
  const repoCounts = m.repos.map((r) => r.repoAlertCount).filter((v) => v != null);
  if (repoCounts.length && repoCounts.every((v) => v === 0) && (A.dependabot.value || 0) > 0) {
    out.push('Repository-level Dependabot alert counts are all zero in this report, although organisations report open alerts — alerts cannot be attributed to individual repositories here. Use Security overview for per-repository detail.');
  }
  if (m.enterprise?.auditEvents != null) out.push(`Only ${fmtInt(m.enterprise.auditEvents)} audit log events were sampled; no audit-log findings are derived from them.`);
  if (m.orgs.some((o) => Object.keys(o.legacyDefaults || {}).length)) {
    out.push('Organisation “enabled for new repositories” security defaults come from GitHub API fields that GitHub deprecated in 2026 in favour of code security configurations. They are shown for reference only and are not scored.');
  }
  const noLang = m.repos.filter((r) => !r.language).length;
  const noBranch = m.repos.filter((r) => !r.defaultBranchFromMeta).length;
  if (noLang || noBranch) out.push(`${fmtInt(noLang)} repositories have no detected language and ${fmtInt(noBranch)} have no default branch in their metadata (possibly empty or documentation-only); for those, the ruleset target branch is used.`);
  out.push('Archived repositories are excluded from repository scoring (they are read-only), but their GHQR findings remain listed.');
  out.push('Scores are calculated by this dashboard from the raw GHQR data using the published scoring model. GHQR finding counts are reproduced exactly.');
  return out;
}

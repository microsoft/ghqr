/* ─── Utilities ─────────────────────────────────────────────────────────── */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const safeUrl = (u) => (typeof u === 'string' && /^https:\/\/[^\s"'<>]+$/i.test(u) ? u : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v) => (typeof v === 'boolean' ? v : null);
const sum = (arr, f = (x) => x) => arr.reduce((t, x) => t + (Number(f(x)) || 0), 0);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const fmtInt = (n) => (n == null ? '—' : Math.round(n).toLocaleString('en-AU'));
const fmtPct = (v) => (v == null || Number.isNaN(v) ? '—' : `${Math.round(v * 100)}%`);
const fmtScore = (v) => (v == null ? '—' : String(Math.round(v)));
const fmtPts = (v) => `${v >= 0 ? '+' : '−'}${Math.abs(v).toFixed(1)}`;
const fmtDate = (d) => (d ? d.toLocaleDateString('en-AU', { day: 'numeric', month: 'short', year: 'numeric' }) : '—');
const fmtMoney = (n) => (n == null ? '—' : `$${Math.round(n).toLocaleString('en-AU')}`);
const plural = (n, one, many) => `${fmtInt(n)} ${n === 1 ? one : many || `${one}s`}`;
const listText = (a) => (a.length <= 1 ? a.join('') : `${a.slice(0, -1).join(', ')} and ${a[a.length - 1]}`);
const relDays = (n) => (n == null ? '—' : n === 0 ? 'today' : n === 1 ? '1 day ago' : `${n} days ago`);
const cap = (s) => String(s || '').replace(/^./, (c) => c.toUpperCase());

function parseDate(s) {
  if (!s) return null;
  let d = new Date(s);
  if (Number.isNaN(d.getTime())) d = new Date(String(s).replace(/ \+0000 UTC$/, 'Z').replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? null : d;
}

/* ─── Icons (hand-drawn 24×24 stroke icons) ─────────────────────────────── */
const ICONS = {
  check: '<path d="M4.5 12.5l4.5 4.5L19.5 6.5"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  alert: '<path d="M12 3.5l9.5 16.5h-19L12 3.5z"/><path d="M12 10v4.5M12 17.5v.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.01"/>',
  shield: '<path d="M12 3l8 3v6c0 4.9-3.4 8.1-8 9-4.6-.9-8-4.1-8-9V6l8-3z"/><path d="M8.8 12.2l2.2 2.2 4.4-4.6"/>',
  branch: '<circle cx="6.5" cy="5.5" r="2.2"/><circle cx="6.5" cy="18.5" r="2.2"/><circle cx="17.5" cy="7.5" r="2.2"/><path d="M6.5 7.7v8.6M17.5 9.7c0 4.3-5.8 3.6-10.2 7"/>',
  key: '<circle cx="8" cy="15" r="4.2"/><path d="M11 12l8.5-8.5M16 7l3 3M14 9l2 2"/>',
  flow: '<circle cx="6" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M8.4 6H15a3 3 0 013 3v6.6M6 8.4V15a3 3 0 003 3h6.6"/>',
  sparkles: '<path d="M12 3l1.7 4.8L18.5 9.5l-4.8 1.7L12 16l-1.7-4.8L5.5 9.5l4.8-1.7L12 3z"/><path d="M18.5 15.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z"/>',
  coin: '<circle cx="12" cy="12" r="9"/><path d="M14.8 9.3c-.5-.9-1.5-1.4-2.8-1.4-1.6 0-2.9.8-2.9 2s1.2 1.7 2.9 2 2.9.8 2.9 2-1.3 2-2.9 2c-1.3 0-2.4-.5-2.9-1.4M12 6.3v11.4"/>',
  activity: '<path d="M3 12h4l3-7.5 4 15 3-7.5h4"/>',
  repo: '<path d="M5.5 4h11A2.5 2.5 0 0119 6.5V20H8a2.5 2.5 0 01-2.5-2.5V4z"/><path d="M5.5 17.5A2.5 2.5 0 018 15h11"/>',
  org: '<path d="M4 21V6.5L12 3l8 3.5V21"/><path d="M9.5 21v-4.5h5V21M8.5 9h.01M12 9h.01M15.5 9h.01M8.5 12.5h.01M12 12.5h.01M15.5 12.5h.01"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2"/>',
  bolt: '<path d="M13 2.5L4.5 13.5H11l-1 8 8.5-11H12l1-8z"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
  download: '<path d="M12 3.5v11M7.5 10.5l4.5 4.5 4.5-4.5M4.5 20h15"/>',
  upload: '<path d="M12 20V9M7.5 13.5L12 9l4.5 4.5M4.5 4h15"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
  moon: '<path d="M20 14.2A8.2 8.2 0 019.8 4 8.2 8.2 0 1020 14.2z"/>',
  play: '<path d="M8 5l11 7-11 7V5z"/>',
  printer: '<path d="M6.5 9V3.5h11V9M6.5 17.5h-2v-7h15v7h-2"/><path d="M8 14h8v6.5H8z"/>',
  external: '<path d="M14 4h6v6M20 4l-8.5 8.5M18 13.5V20H4V6h6.5"/>',
  chevron: '<path d="M9 6l6 6-6 6"/>',
  map: '<rect x="3.5" y="3.5" width="17" height="17" rx="2"/><path d="M3.5 12h8.5M12 3.5v17M12 8.5h8.5M12 15.5h8.5"/>',
  list: '<path d="M9 6.5h11M9 12h11M9 17.5h11M4.5 6.5h.01M4.5 12h.01M4.5 17.5h.01"/>',
  flag: '<path d="M5.5 21V4M5.5 4.5h11l-2.2 4 2.2 4h-11"/>',
  trend: '<path d="M3.5 17l6-6 4 4 7-7.5M15 7.5h5.5V13"/>',
  lock: '<rect x="5" y="11" width="14" height="9.5" rx="2"/><path d="M8.5 11V7.5a3.5 3.5 0 017 0V11"/>',
  users: '<circle cx="9" cy="8" r="3.4"/><path d="M2.8 20c.8-3.5 3.2-5.4 6.2-5.4s5.4 1.9 6.2 5.4"/><path d="M15.5 4.8a3.4 3.4 0 010 6.4M17.6 14.9c1.8.8 3 2.5 3.4 5.1"/>',
  bug: '<rect x="7" y="8" width="10" height="12" rx="5"/><path d="M12 12v8M7 13H3.5M20.5 13H17M7.5 17.5l-3 2M16.5 17.5l3 2M8.5 8.5L6.5 5M15.5 8.5l2-3.5"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  data: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
  road: '<path d="M7 3.5L4 20.5M17 3.5l3 17M12 4.5v2.5M12 10.5v3M12 17v3"/>',
  close: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  copilot: '<path d="M5 10.5c0-3.5 3-6 7-6s7 2.5 7 6v3.5c0 3-3 5.5-7 5.5s-7-2.5-7-5.5v-3.5z"/><circle cx="9.3" cy="12.2" r="1.2"/><circle cx="14.7" cy="12.2" r="1.2"/><path d="M3 12.5v2M21 12.5v2"/>',
};
const icon = (name, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;

/* ─── Severity, score bands and labels ──────────────────────────────────── */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const normSev = (s) => {
  const v = String(s || '').toLowerCase();
  if (SEVERITIES.includes(v)) return v;
  return v === 'moderate' ? 'medium' : 'info';
};
const sevPill = (s, extra = '') => `<span class="sev sev-${s}">${SEV_LABEL[s]}${extra}</span>`;

const BANDS = [
  { min: 80, key: 'green', label: 'Strong' },
  { min: 60, key: 'amber', label: 'Fair' },
  { min: 0, key: 'red', label: 'At risk' },
];
const band = (v) => (v == null ? { key: 'none', label: 'Not assessed' } : BANDS.find((b) => v >= b.min));

const SCORE_STOPS = [[40, [251, 113, 133]], [62, [251, 191, 36]], [86, [52, 211, 153]]];
function scoreRGB(v) {
  if (v == null) return [100, 116, 139];
  const s = SCORE_STOPS;
  if (v <= s[0][0]) return s[0][1];
  if (v >= s[s.length - 1][0]) return s[s.length - 1][1];
  for (let i = 0; i < s.length - 1; i++) {
    const [a, ca] = s[i];
    const [b, cb] = s[i + 1];
    if (v >= a && v <= b) {
      const t = (v - a) / (b - a);
      return ca.map((c, k) => Math.round(c + (cb[k] - c) * t));
    }
  }
  return s[0][1];
}
const scoreColor = (v, a = 1) => `rgba(${scoreRGB(v).join(',')},${a})`;

const SCOPE_LABEL = { enterprise: 'Enterprise', org: 'Organisation', repo: 'Repository', budget: 'Budget' };

const CATEGORY_LABEL = {
  dependencies: 'Dependency management',
  branch_protection: 'Branch protection',
  security: 'Security & vulnerabilities',
  access_control: 'Access control & ownership',
  budget: 'Budget governance',
  community: 'Community health & docs',
  features: 'Repository features',
  maintenance: 'Repository maintenance',
  access: 'Repository status',
  copilot_security: 'Copilot security & compliance',
  copilot_cost: 'Copilot seats & cost',
  actions: 'Actions & CI/CD',
};
const catLabel = (c) => CATEGORY_LABEL[c] || cap(String(c || 'other').replace(/_/g, ' '));

const RULE_TITLES = {
  'org-alert-001': 'Critical Dependabot alerts open in the organisation',
  'org-alert-002': 'High-severity Dependabot alerts open in the organisation',
  'org-alert-004': 'Code scanning alerts open in the organisation',
};

const DOMAINS = [
  { id: 'vuln', title: 'Vulnerability management', icon: 'bug', tab: 'security', blurb: 'Open Dependabot, code scanning and secret scanning alerts, plus dependency-update coverage.' },
  { id: 'branch', title: 'Branch protection & review', icon: 'branch', tab: 'repos', blurb: 'Default-branch rulesets, reviews, status checks, signed commits and code owners.' },
  { id: 'identity', title: 'Identity & access', icon: 'key', tab: 'orgs', blurb: 'Managed identities, repository visibility, base permissions and security managers.' },
  { id: 'actions', title: 'Actions & CI/CD', icon: 'flow', tab: 'orgs', blurb: 'Allowed actions, workflow token permissions and pull-request approval by workflows.' },
  { id: 'hygiene', title: 'Repository hygiene', icon: 'sparkles', tab: 'repos', blurb: 'Descriptions, topics, security policies, branch conventions and housekeeping.' },
  { id: 'governance', title: 'Copilot & cost governance', icon: 'coin', tab: 'copilot', blurb: 'Copilot public-code policy and enterprise budget guardrails.' },
];

const DOCS = {
  dependabot: 'https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts',
  versionUpdates: 'https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/about-dependabot-version-updates',
  atScale: 'https://docs.github.com/en/code-security/securing-your-organization/introduction-to-securing-your-organization-at-scale/about-enabling-security-features-at-scale',
  codeScanning: 'https://docs.github.com/en/enterprise-cloud@latest/code-security/code-scanning/managing-code-scanning-alerts/about-code-scanning-alerts',
  secretScanning: 'https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning',
  securityOverview: 'https://docs.github.com/en/code-security/security-overview/about-security-overview',
  rulesets: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets',
  rules: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets',
  orgRulesets: 'https://docs.github.com/en/organizations/managing-organization-settings/managing-rulesets-for-repositories-in-your-organization',
  protectedBranches: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches',
  codeowners: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners',
  emu: 'https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/understanding-iam-for-enterprises/about-enterprise-managed-users',
  repoCreation: 'https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization',
  securityManagers: 'https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization',
  basePermissions: 'https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization',
  actionsPolicy: 'https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization',
  token: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication',
  signoff: 'https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization',
  defaultBranch: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-branches-in-your-repository/changing-the-default-branch',
  copilotPolicies: 'https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-policies-for-copilot-in-your-organization',
  budgets: 'https://docs.github.com/en/enterprise-cloud@latest/billing/using-the-new-billing-platform/about-the-new-billing-platform-for-enterprises',
  metadata: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-repository-metadata',
  topics: 'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics',
  securityPolicy: 'https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository',
  autoDelete: 'https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches',
  discussions: 'https://docs.github.com/en/discussions/quickstart',
  dataResidency: 'https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/about-github-enterprise-cloud-with-data-residency',
};

/* Areas the GHQR report lists as not verifiable through the API. */
const MANUAL_CHECKS = [
  ['Audit log streaming', 'Connected to SIEM', 'Enterprise → Settings → Audit log'],
  ['Secret scanning alerts', 'Open critical alerts reviewed and resolved', 'Repo → Security → Secret scanning'],
  ['Secret scanning: custom patterns', 'Org/enterprise-level custom patterns defined', 'Org → Settings → Code security → Secret scanning'],
  ['Secret scanning: bypass requests', 'Bypass request reviewers configured for push protection', 'Org → Settings → Code security → Secret scanning'],
  ['Code scanning: default setup', 'Default setup enabled on all active repositories', 'Repo → Settings → Code security → Code scanning'],
  ['Code scanning: alert triage', 'Open high/critical code scanning alerts reviewed', 'Repo → Security → Code scanning'],
  ['Code scanning: tool coverage', 'All relevant languages covered by a scanning tool', 'Repo → Security → Code scanning'],
  ['Dependency review', 'dependency-review-action present in PR workflows', 'Repo → .github/workflows/'],
  ['Actions: self-hosted runners', 'Not attached to public repositories', 'Repo → Settings → Actions → Runners'],
  ['Branch protection: enforce admins', 'Enabled', 'Repo → Settings → Branches'],
  ['Environment protection rules', 'Reviewers configured', 'Repo → Settings → Environments'],
  ['SAML SSO enforcement & SCIM', 'SSO enforced; SCIM provisioning active', 'Org → Settings → Authentication security'],
  ['IP allow list', 'Configured and enabled', 'Org → Settings → Authentication security'],
  ['Organisation webhooks', 'SSL verification enabled, shared secret set on all hooks', 'Org → Settings → Webhooks'],
  ['Organisation-level rulesets', 'At least one ruleset defined for repository governance', 'Org → Settings → Rules → Rulesets'],
];

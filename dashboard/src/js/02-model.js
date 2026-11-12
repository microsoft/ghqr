/* ─── Model: normalise the raw GHQR JSON ───────────────────────────────── */
function buildModel(raw, sourceName) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('The file is not a JSON object.');
  if (!raw.repositories && !raw.organizations && !raw.enterprises) {
    throw new Error('This does not look like a GHQR report — no enterprises, organizations or repositories were found.');
  }
  const generatedAt = parseDate(raw.generated_at);
  const now = generatedAt || new Date();
  const [entSlug, entRaw] = Object.entries(raw.enterprises || {})[0] || [null, null];
  const orgInfo = Object.fromEntries((entRaw?.organizations || []).map((o) => [o.login, o]));
  const findings = [];

  const collect = (scope, entity, org, obj) => {
    for (const [key, val] of Object.entries(obj || {})) {
      if (!(key === 'evaluation' || key.endsWith('_evaluation')) || !val || typeof val !== 'object') continue;
      for (const r of val.recommendations || []) {
        findings.push({
          uid: findings.length, scope, entity, org, source: key,
          ruleId: r.rule_id || null,
          severity: normSev(r.severity),
          category: r.category || 'other',
          issue: String(r.issue || ''),
          recommendation: String(r.recommendation || ''),
          learnMore: safeUrl(r.learn_more),
        });
      }
    }
  };

  const alertsOf = (a) => ({
    available: !!a && a.available !== false && Object.keys(a).length > 0,
    critical: num(a?.critical_dependabot),
    high: num(a?.high_dependabot),
    dependabot: num(a?.open_dependabot_alerts),
    codeScanning: num(a?.open_code_scanning_alerts),
    secretScanning: num(a?.open_secret_scanning_alerts),
  });

  let enterprise = null;
  if (entRaw) {
    collect('enterprise', entSlug, null, entRaw);
    const s = entRaw.settings || {};
    enterprise = {
      slug: entSlug,
      name: s.name || entSlug,
      description: s.description || '',
      url: safeUrl(s.url),
      createdAt: parseDate(s.created_at),
      emu: bool(s.emu_enabled),
      alerts: alertsOf(entRaw.security_alerts),
      budgetsAvailable: !!entRaw.budgets && entRaw.budgets.available !== false,
      budgets: (entRaw.budgets?.budgets || []).map((b, i) => ({
        id: b.id || `budget-${i}`,
        scope: b.budget_scope || 'unknown',
        entity: b.budget_entity_name || '',
        amount: num(b.budget_amount),
        type: b.budget_type || '',
        sku: b.budget_product_sku || (Array.isArray(b.budget_product_skus) ? b.budget_product_skus.join(', ') : ''),
        alerting: !!b.budget_alerting?.will_alert,
        recipients: Array.isArray(b.budget_alerting?.alert_recipients) ? b.budget_alerting.alert_recipients : [],
        prevent: !!b.prevent_further_usage,
      })),
      auditEvents: num(entRaw.audit_log?.total_events_scanned),
      orgList: entRaw.organizations || [],
    };
  }

  const stubOrg = (login) => ({
    login, stub: true, raw: {}, description: orgInfo[login]?.description || '', url: safeUrl(orgInfo[login]?.url),
    alerts: alertsOf(null), securityManager: null, allowedActions: null, tokenPerm: null, actionsCanApprove: null,
    basePermission: null, publicCreation: null, webSignoff: null, emu: null, legacyDefaults: {}, copilot: null,
    repos: [], findings: [],
  });

  const orgMap = new Map();
  for (const [login, o] of Object.entries(raw.organizations || {})) {
    const sec = o.settings?.security || {};
    const vis = o.settings?.visibility || {};
    const ap = o.actions_permissions || {};
    const cp = o.copilot;
    collect('org', login, login, o);
    orgMap.set(login, {
      login, stub: false, raw: o,
      description: orgInfo[login]?.description || '',
      url: safeUrl(orgInfo[login]?.url),
      alerts: alertsOf(o.security_alerts),
      securityManager: bool(o.security_managers?.has_security_manager),
      allowedActions: ap.allowed_actions ?? null,
      tokenPerm: ap.default_workflow_permissions ?? null,
      actionsCanApprove: bool(ap.can_approve_pull_request_reviews),
      basePermission: vis.default_repository_permission ?? null,
      publicCreation: bool(vis.members_can_create_public_repositories),
      webSignoff: bool(sec.web_commit_signoff_required),
      emu: bool(sec.emu_enabled),
      twoFactor: bool(sec.two_factor_requirement_enabled),
      legacyDefaults: Object.fromEntries(Object.entries(sec).filter(([k]) => k.endsWith('_for_new_repos'))),
      copilot: cp ? {
        seats: num(cp.total_seats), active: num(cp.active_this_cycle), inactive: num(cp.inactive_this_cycle),
        seatMgmt: cp.seat_management_setting || null, ideChat: cp.ide_chat || null, cli: cp.cli || null,
        platformChat: cp.platform_chat || null, publicCode: cp.public_code_suggestions || null, billing: bool(cp.billing_enabled),
      } : null,
      repos: [], findings: [],
    });
  }

  const repos = [];
  for (const [full, r] of Object.entries(raw.repositories || {})) {
    const org = r.organization || full.split('/')[0];
    const rs = r.ruleset_protection || null;
    const bp = r.branch_protection || null;
    const prot = rs?.protected ? rs : bp?.protected ? bp : null;
    const reviews = prot?.required_pull_request_reviews || null;
    const checks = prot?.required_status_checks || null;
    const contexts = Array.isArray(checks?.contexts) ? checks.contexts : [];
    const pushedAt = parseDate(r.pushed_at);
    const rec = {
      full, org, raw: r,
      name: r.name || full.split('/').slice(1).join('/'),
      archived: !!r.access?.archived,
      visibility: String(r.access?.visibility || (r.access?.private === false ? 'PUBLIC' : 'PRIVATE')).toUpperCase(),
      fork: !!r.access?.fork,
      isProtected: !!prot,
      protectedBy: rs?.protected ? 'ruleset' : bp?.protected ? 'legacy' : null,
      rulesetCount: num(rs?.ruleset_count) || 0,
      forcePushBlocked: !!prot && prot.allow_force_pushes === false,
      deletionBlocked: !!prot && prot.allow_deletions === false,
      approvals: num(reviews?.required_approving_review_count) || 0,
      prRequired: !!reviews,
      dismissStale: !!reviews?.dismiss_stale_reviews,
      codeOwnerReviews: !!reviews?.require_code_owner_reviews,
      contexts,
      statusChecks: contexts.length > 0,
      strictChecks: !!checks?.strict,
      signed: !!prot?.required_signatures,
      linear: !!prot?.required_linear_history,
      codeowners: !!r.security?.codeowners_file?.exists,
      securityMd: !!r.security?.security_policy?.enabled,
      dependabotAlerts: !!(r.security?.dependabot_alerts?.enabled ?? r.security?.vulnerability_alerts?.enabled),
      repoAlertCount: num(r.security?.dependabot_alerts?.total_open_alerts),
      dependabotConfig: !!r.dependabot_config?.exists,
      description: String(r.description || '').trim(),
      topics: Array.isArray(r.metadata?.topics) ? r.metadata.topics : [],
      language: r.metadata?.language || null,
      license: r.metadata?.license || null,
      defaultBranch: r.metadata?.default_branch || prot?.branch || rs?.branch || '',
      defaultBranchFromMeta: !!r.metadata?.default_branch,
      pushedAt,
      daysSincePush: pushedAt ? Math.max(0, Math.floor((now - pushedAt) / 86400000)) : null,
      deleteBranchOnMerge: r.access?.delete_branch_on_merge !== false,
      hasIssues: !!r.basic_features?.has_issues,
      hasDiscussions: !!(r.basic_features?.has_discussions || r.discussion_settings?.enabled),
      hasWiki: !!r.basic_features?.has_wiki,
      findings: [],
    };
    if (!orgMap.has(org)) orgMap.set(org, stubOrg(org));
    orgMap.get(org).repos.push(rec);
    collect('repo', full, org, r);
    repos.push(rec);
  }

  const repoMap = new Map(repos.map((r) => [r.full, r]));
  for (const f of findings) {
    if (f.scope === 'repo') repoMap.get(f.entity)?.findings.push(f);
    else if (f.scope === 'org') orgMap.get(f.entity)?.findings.push(f);
  }
  const orgs = [...orgMap.values()];
  for (const o of orgs) o.activeRepoCount = o.repos.filter((r) => !r.archived).length;

  // Best-available alert totals: org-level sums vs enterprise figures (either can be a capped sample).
  const withAlerts = orgs.filter((o) => o.alerts.available);
  const alerts = {};
  for (const k of ['critical', 'high', 'dependabot', 'codeScanning', 'secretScanning']) {
    const orgSum = withAlerts.length ? sum(withAlerts, (o) => o.alerts[k] || 0) : null;
    const entVal = enterprise?.alerts.available ? enterprise.alerts[k] : null;
    const value = orgSum == null ? entVal : entVal == null ? orgSum : Math.max(orgSum, entVal);
    const cappedOrgs = withAlerts.filter((o) => o.alerts[k] === 100).map((o) => o.login);
    alerts[k] = {
      value, orgSum, entVal, cappedOrgs,
      entCapped: entVal === 100 && orgSum != null && orgSum >= 100,
      maybeMore: cappedOrgs.length > 0 || (value === entVal && entVal === 100),
    };
  }

  let webBase = null;
  try {
    const u = enterprise?.url || orgs.find((o) => o.url)?.url;
    if (u) webBase = new URL(u).origin;
  } catch { webBase = null; }

  return { raw, sourceName, generatedAt, now, enterprise, orgs, repos, repoMap, orgMap, findings, alerts, webBase };
}

const alertText = (a) => (a.value == null ? '—' : `${fmtInt(a.value)}${a.maybeMore ? '+' : ''}`);
const repoUrl = (m, r) => (m.webBase ? safeUrl(`${m.webBase}/${r.full.split('/').map(encodeURIComponent).join('/')}`) : null);
const orgUrl = (m, o) => o.url || (m.webBase ? safeUrl(`${m.webBase}/${encodeURIComponent(o.login)}`) : null);

/* Group GHQR findings the way the GHQR report does: one row per rule, with affected entities. */
function groupFindings(m) {
  const groups = new Map();
  for (const f of m.findings) {
    const key = `${f.scope}|${f.ruleId || `${f.category}|${f.issue.replace(/\d[\d,]*/g, '#')}`}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key, scope: f.scope, ruleId: f.ruleId, category: f.category, severity: f.severity,
        recommendation: f.recommendation, learnMore: f.learnMore, items: [], issues: new Set(),
      };
      groups.set(key, g);
    }
    g.items.push(f);
    g.issues.add(f.issue);
    if (SEV_RANK[f.severity] < SEV_RANK[g.severity]) g.severity = f.severity;
  }
  const out = [...groups.values()];
  for (const g of out) {
    g.varied = g.issues.size > 1;
    g.title = g.varied ? RULE_TITLES[g.ruleId] || g.items[0].issue.replace(/\b\d[\d,]*\b/g, 'N') : g.items[0].issue;
    g.positive = /^no action required/i.test(g.recommendation);
    g.id = `g${out.indexOf(g)}`;
  }
  return out.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.items.length - a.items.length);
}

function countBySeverity(list) {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of list) c[f.severity] += 1;
  return c;
}

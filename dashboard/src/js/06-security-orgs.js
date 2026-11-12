/* ─── View: Security ──────────────────────────────────────────────────── */
function renderSecurity(m) {
  const A = m.alerts;
  const level = A.critical.value ? 3 : A.high.value ? 2 : (A.dependabot.value || 0) + (A.codeScanning.value || 0) ? 1 : 0;
  const levelText = ['Low', 'Moderate', 'High', 'Critical'][level];
  const levelWhy = [
    'No open critical or high alerts were reported.',
    'Open alerts exist, but none are critical or high severity.',
    'High-severity alerts are open — remediate within your SLA.',
    `${fmtInt(A.critical.value)} critical Dependabot alert${A.critical.value === 1 ? ' is' : 's are'} open — remediate immediately.`,
  ][level];
  const orgs = m.orgs.filter((o) => !o.stub);
  const depOrgs = orgs.filter((o) => (o.alerts.dependabot || 0) > 0).sort((a, b) => b.alerts.dependabot - a.alerts.dependabot);
  const csOrgs = orgs.filter((o) => (o.alerts.codeScanning || 0) > 0).sort((a, b) => b.alerts.codeScanning - a.alerts.codeScanning);
  const clean = orgs.filter((o) => o.alerts.available && !o.alerts.dependabot && !o.alerts.codeScanning && !o.alerts.secretScanning);
  const depMax = Math.max(1, ...depOrgs.map((o) => o.alerts.dependabot));
  const active = m.repos.filter((r) => !r.archived);
  const c = (id) => m.controlMap.get(id);
  const alertFindings = m.groups.filter((g) => ['dependencies'].includes(g.category) || /alert/.test(g.ruleId || ''));

  const tiles = [
    { label: 'Critical Dependabot', k: 'critical', sev: 'critical', icon: 'alert' },
    { label: 'High Dependabot', k: 'high', sev: 'high', icon: 'bug' },
    { label: 'All open Dependabot', k: 'dependabot', sev: 'medium', icon: 'bug' },
    { label: 'Code scanning', k: 'codeScanning', sev: 'high', icon: 'eye' },
    { label: 'Secret scanning', k: 'secretScanning', sev: 'critical', icon: 'lock' },
  ].map((t) => ({ ...t, a: A[t.k], affected: orgs.filter((o) => (o.alerts[t.k] || 0) > 0).length }));

  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('bug')} Security</div><h2>Vulnerability exposure</h2>
    <p>Open alerts reported by Dependabot, code scanning and secret scanning, and how well the estate is covered.</p></div></section>

  <section class="grid-sec">
    <div class="card reveal risk-card level-${level}">
      <div class="card-head"><h3>${icon('target')} Current risk level</h3></div>
      ${riskMeter(level, { size: 340 })}
      <div class="risk-text"><b>${levelText}</b><p>${esc(levelWhy)}</p></div>
    </div>
    <div class="alert-tiles">
      ${tiles.map((t) => `<div class="alert-tile reveal ${t.a.value ? `on sev-bg-${t.sev}` : 'clear'}">
        <div class="at-top">${icon(t.icon)}<span>${esc(t.label)}</span></div>
        <div class="at-num" data-count="${t.a.value ?? ''}" data-suffix="${t.a.maybeMore ? '+' : ''}">${alertText(t.a)}</div>
        <div class="at-sub">${t.a.value ? `${plural(t.affected, 'organisation')} affected` : `${icon('check')} none open`}</div>
      </div>`).join('')}
      <div class="alert-tile reveal clear">
        <div class="at-top">${icon('shield')}<span>Clean organisations</span></div>
        <div class="at-num" data-count="${clean.length}">${fmtInt(clean.length)}</div>
        <div class="at-sub">of ${plural(orgs.length, 'organisation')} with no open alerts</div>
      </div>
    </div>
  </section>

  <section class="grid-2">
    <div class="card reveal">
      <div class="card-head"><h3>${icon('bug')} Dependabot alerts by organisation</h3>
        <div class="mini-legend"><span><i style="--c:var(--sev-critical)"></i>Critical</span><span><i style="--c:var(--sev-high)"></i>High</span><span><i style="--c:var(--sev-medium)"></i>Medium / low</span></div></div>
      ${depOrgs.length ? `<div class="stackbars">${depOrgs.map((o, i) => {
        const cr = o.alerts.critical || 0, hi = o.alerts.high || 0, other = Math.max(0, o.alerts.dependabot - cr - hi);
        return `<button class="sb-row" data-open-org="${esc(o.login)}"><span class="sb-label">${esc(o.login)}</span>
          <span class="sb-track"><span class="sb-fill" style="--w:${((100 * o.alerts.dependabot) / depMax).toFixed(1)}%;--i:${i}">
            ${[[cr, 'critical', 'Critical'], [hi, 'high', 'High'], [other, 'medium', 'Medium / low']].filter(([v]) => v).map(([v, s, l]) => `<i style="flex:${v};--c:var(--sev-${s})" data-tip="${esc(`${o.login} · ${l}: ${fmtInt(v)}`)}"></i>`).join('')}
          </span></span><b>${fmtInt(o.alerts.dependabot)}</b></button>`;
      }).join('')}</div>` : `<div class="empty-state">${icon('check')} No open Dependabot alerts.</div>`}
    </div>
    <div class="card reveal">
      <div class="card-head"><h3>${icon('eye')} Code scanning alerts by organisation</h3></div>
      ${csOrgs.length ? hbars(csOrgs.map((o) => ({ label: o.login, value: o.alerts.codeScanning, color: 'linear-gradient(90deg,var(--sev-medium),var(--sev-high))', attrs: `data-open-org="${esc(o.login)}"`, valueHtml: `${fmtInt(o.alerts.codeScanning)}${o.alerts.codeScanning === 100 ? '<sup data-tip="Exactly 100 — likely a collection page limit">+</sup>' : ''}` }))) : `<div class="empty-state">${icon('check')} No open code scanning alerts.</div>`}
      ${clean.length ? `<div class="clean-orgs"><span class="muted">No open alerts:</span> ${clean.map((o) => `<button class="org-chip" data-open-org="${esc(o.login)}">${icon('check')}${esc(o.login)}</button>`).join('')}</div>` : ''}
    </div>
  </section>

  <section class="card reveal">
    <div class="card-head"><h3>${icon('shield')} Coverage</h3><span class="muted">share of active repositories or organisations with the control in place</span></div>
    <div class="coverage-rings">
      ${[['vuln-dependabot', 'Dependabot alerts'], ['vuln-updates', 'Version updates (dependabot.yml)'], ['id-secmgr', 'Security managers assigned'], ['bp-checks', 'Required CI checks'], ['bp-codeowners', 'CODEOWNERS present']]
        .map(([id, label]) => c(id) ? `<button class="cov" data-open-control="${id}">${ring(c(id).rate, { size: 112, label })}<b>${esc(label)}</b><small>${esc(passPhrase(c(id)))}</small></button>` : '').join('')}
    </div>
  </section>

  <section class="grid-2">
    <div class="card reveal">
      <div class="card-head"><h3>${icon('list')} GHQR alert findings</h3></div>
      <div class="flist">${alertFindings.map((g) => g.items.map((f) => `<div class="frow sev-l-${f.severity}">${sevPill(f.severity)}<div><b>${esc(f.issue)}</b><small>${esc(SCOPE_LABEL[f.scope])} · ${esc(f.entity)}</small></div></div>`).join('')).join('') || '<div class="empty-state">No alert findings.</div>'}</div>
    </div>
    <div class="card reveal note-card">
      <div class="card-head"><h3>${icon('data')} Reading these numbers</h3></div>
      <ul class="notes">${m.caveats.filter((t) => /alert/i.test(t)).map((t) => `<li>${esc(t)}</li>`).join('')}
        <li>${esc(c('vuln-secret')?.note || '')}</li></ul>
      <a class="link" href="${DOCS.securityOverview}" target="_blank" rel="noopener noreferrer">${icon('external')} About Security overview</a>
    </div>
  </section>`;
}

/* ─── View: Organisations ─────────────────────────────────────────────── */
const ORG_COLUMNS = [
  { group: 'Posture', label: 'Health', cell: (o) => ({ html: `<span class="score-pill" style="--c:${scoreColor(o.score)}">${fmtScore(o.score)}</span>`, tip: `Health score ${fmtScore(o.score)}` }) },
  { group: 'Posture', label: 'Repos', cell: (o) => ({ html: `<b>${fmtInt(o.repos.length)}</b>`, tip: `${o.activeRepoCount} active, ${o.repos.length - o.activeRepoCount} archived` }) },
  { group: 'Open alerts', label: 'Critical', cell: (o) => alertCell(o.alerts.critical, 'critical') },
  { group: 'Open alerts', label: 'High', cell: (o) => alertCell(o.alerts.high, 'high') },
  { group: 'Open alerts', label: 'Code scan', cell: (o) => alertCell(o.alerts.codeScanning, 'high') },
  { group: 'Open alerts', label: 'Secrets', cell: (o) => alertCell(o.alerts.secretScanning, 'critical') },
  { group: 'Access', label: 'Base perm.', cell: (o) => okCell(o.basePermission == null ? null : ['read', 'none'].includes(String(o.basePermission).toLowerCase()), o.basePermission || '—', `Base permission: ${o.basePermission}`) },
  { group: 'Access', label: 'No public', cell: (o) => okCell(o.publicCreation == null ? null : !o.publicCreation, null, 'Members cannot create public repositories') },
  { group: 'Access', label: 'Sec. mgr', cell: (o) => okCell(o.securityManager, null, 'Security manager role assigned') },
  { group: 'Actions', label: 'Allowed', cell: (o) => okCell(o.allowedActions == null ? null : o.allowedActions !== 'all', o.allowedActions || '—', `Allowed actions: ${o.allowedActions}`) },
  { group: 'Actions', label: 'Token', cell: (o) => okCell(o.tokenPerm == null ? null : o.tokenPerm === 'read', o.tokenPerm || '—', `Default GITHUB_TOKEN: ${o.tokenPerm}`) },
  { group: 'Actions', label: 'No PR approve', cell: (o) => okCell(o.actionsCanApprove == null ? null : !o.actionsCanApprove, null, 'Workflows cannot approve pull requests') },
  { group: 'Repo coverage', label: 'CI checks', cell: (o) => pctCell(o, 'bp-checks') },
  { group: 'Repo coverage', label: 'CODEOWNERS', cell: (o) => pctCell(o, 'bp-codeowners') },
  { group: 'Repo coverage', label: 'dependabot.yml', cell: (o) => pctCell(o, 'vuln-updates') },
  { group: 'Repo coverage', label: 'Description', cell: (o) => pctCell(o, 'hy-desc') },
  { group: 'Copilot', label: 'Seats', cell: (o) => ({ html: o.copilot ? `<b>${fmtInt(o.copilot.seats)}</b>` : '—', tip: o.copilot ? `Seat management: ${o.copilot.seatMgmt}` : 'No Copilot data' }) },
];
let orgCtx = null;
function alertCell(v, sev) {
  if (v == null) return { html: '<span class="na">—</span>', tip: 'Not available' };
  return v ? { cls: `heat-${sev}`, html: `<b>${fmtInt(v)}${v === 100 ? '+' : ''}</b>`, tip: `${fmtInt(v)} open` } : { cls: 'heat-ok', html: icon('check'), tip: 'None open' };
}
function okCell(ok, text, tip) {
  if (ok == null) return { html: '<span class="na">—</span>', tip: 'Not available' };
  return { cls: ok ? 'heat-ok' : 'heat-bad', html: text ? `<span class="cell-txt">${esc(text)}</span>` : icon(ok ? 'check' : 'x'), tip: `${tip} — ${ok ? 'in place' : 'not in place'}` };
}
function pctCell(o, id) {
  const c = orgCtx.controlMap.get(id);
  const ents = c ? c.known.filter((r) => r.org === o.login) : [];
  if (!ents.length) return { html: '<span class="na">—</span>', tip: 'No active repositories' };
  const p = ents.filter((r) => c.passSet.has(r)).length / ents.length;
  return { html: `<span class="pct" style="--c:${scoreColor(p * 100)};--p:${(p * 100).toFixed(0)}%">${fmtPct(p)}</span>`, tip: `${c.title}: ${ents.filter((r) => c.passSet.has(r)).length} of ${ents.length} active repositories` };
}

function renderOrgs(m) {
  orgCtx = m;
  const orgs = m.orgs.filter((o) => !o.stub || o.repos.length).sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  const groups = [...new Set(ORG_COLUMNS.map((c) => c.group))];
  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('org')} Organisations</div><h2>How each organisation measures up</h2>
    <p>Health scores combine organisation settings with the posture of the organisation’s active repositories.<span class="hint"> Click any organisation for detail.</span></p></div></section>

  <section class="org-cards">${orgs.map((o) => {
    const b = band(o.score);
    const alerts = [['critical', o.alerts.critical, 'critical'], ['high', o.alerts.high, 'high'], ['code scanning', o.alerts.codeScanning, 'medium']].filter(([, v]) => v);
    return `<button class="org-card card reveal glow-${b.key}" data-open-org="${esc(o.login)}">
      <div class="oc-top"><div><b>${esc(o.login)}</b><small>${esc(o.description || '')}</small></div>${gauge(o.score, { size: 92, stroke: 8 })}</div>
      <div class="oc-stats"><span>${icon('repo')} ${plural(o.repos.length, 'repo')}</span><span>${icon('list')} ${plural(o.findings.length + sum(o.repos, (r) => r.findings.length), 'finding')}</span></div>
      <div class="oc-alerts">${alerts.length ? alerts.map(([l, v, s]) => `<span class="sev sev-${s}">${fmtInt(v)}${v === 100 ? '+' : ''} ${l}</span>`).join('') : `<span class="ok-chip">${icon('check')} No open alerts</span>`}</div>
    </button>`;
  }).join('')}</section>

  <section class="card reveal">
    <div class="card-head"><div><h3>${icon('map')} Control heatmap</h3><p class="muted">Green is in place, red is a gap. Percentages show the share of an organisation’s active repositories meeting the control.</p></div></div>
    <div class="table-wrap"><table class="heatmap">
      <thead><tr><th rowspan="2" class="sticky-col">Organisation</th>${groups.map((g) => `<th colspan="${ORG_COLUMNS.filter((c) => c.group === g).length}" class="grp">${esc(g)}</th>`).join('')}</tr>
      <tr>${ORG_COLUMNS.map((c) => `<th>${esc(c.label)}</th>`).join('')}</tr></thead>
      <tbody>${orgs.map((o) => `<tr data-open-org="${esc(o.login)}"><th class="sticky-col"><b>${esc(o.login)}</b></th>${ORG_COLUMNS.map((col) => { const x = col.cell(o); return `<td class="${x.cls || ''}" data-tip="${esc(x.tip || '')}">${x.html}</td>`; }).join('')}</tr>`).join('')}</tbody>
    </table></div>
  </section>`;
}

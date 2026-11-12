/* ─── View: Copilot & cost ────────────────────────────────────────────── */
function policyChip(v, goodWhen) {
  if (!v) return '<span class="na">—</span>';
  const good = goodWhen ? goodWhen(v) : null;
  return `<span class="pchip ${good == null ? '' : good ? 'good' : 'bad'}">${esc(String(v).replace(/_/g, ' '))}</span>`;
}

function renderCopilot(m) {
  const orgs = m.orgs.filter((o) => o.copilot);
  const seats = sum(orgs, (o) => o.copilot.seats || 0);
  const act = sum(orgs, (o) => o.copilot.active || 0);
  const inact = sum(orgs, (o) => o.copilot.inactive || 0);
  const withSeats = orgs.filter((o) => (o.copilot.seats || 0) > 0).length;
  const blocked = orgs.filter((o) => o.copilot.publicCode === 'block').length;
  const budgets = m.enterprise?.budgets || [];
  const cpFindings = m.groups.filter((g) => /^copilot/.test(g.category));
  const budFindings = m.groups.filter((g) => g.category === 'budget');
  const scopeIcon = { enterprise: 'org', user: 'users', multi_user_customer: 'users', organization: 'org', repository: 'repo', cost_center: 'coin' };

  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('copilot')} Copilot &amp; cost</div><h2>AI adoption and spend guardrails</h2>
    <p>Copilot seat usage and policies per organisation, and the budgets that keep metered spend under control.</p></div></section>

  <section class="kpis">
    ${kpiTile({ icon: 'copilot', label: 'Seats assigned', value: fmtInt(seats), count: seats, sub: `${plural(withSeats, 'organisation')} with seats` })}
    ${kpiTile({ icon: 'activity', label: 'Active this cycle', value: fmtInt(act), count: act, sub: `${fmtInt(inact)} inactive`, tone: seats && act / seats >= 0.8 ? 'good' : '' })}
    ${kpiTile({ icon: 'shield', label: 'Public-code matches blocked', value: `${fmtInt(blocked)}/${fmtInt(orgs.length)}`, sub: 'organisations', tone: blocked === orgs.length ? 'good' : 'warn' })}
    ${kpiTile({ icon: 'coin', label: 'Budgets configured', value: fmtInt(budgets.length), count: budgets.length, sub: `${fmtInt(budgets.filter((b) => b.alerting).length)} alerting · ${fmtInt(budgets.filter((b) => b.prevent).length)} hard caps` })}
  </section>

  <section class="card reveal">
    <div class="card-head"><h3>${icon('copilot')} Copilot by organisation</h3><span class="muted">policy values as reported by GHQR</span></div>
    <div class="table-wrap"><table class="grid-table compact">
      <thead><tr><th>Organisation</th><th>Seats</th><th>Active</th><th>Seat management</th><th>IDE chat</th><th>CLI</th><th>Platform chat</th><th>Public-code suggestions</th></tr></thead>
      <tbody>${orgs.map((o) => { const c = o.copilot; return `<tr data-open-org="${esc(o.login)}"><td><b>${esc(o.login)}</b></td>
        <td><b>${fmtInt(c.seats)}</b></td><td>${fmtInt(c.active)}</td>
        <td>${policyChip(c.seatMgmt, (v) => v !== 'unconfigured')}</td><td>${policyChip(c.ideChat)}</td><td>${policyChip(c.cli)}</td><td>${policyChip(c.platformChat)}</td>
        <td>${policyChip(c.publicCode, (v) => v === 'block')}</td></tr>`; }).join('')}</tbody>
    </table></div>
  </section>

  <section class="grid-2">
    <div class="card reveal">
      <div class="card-head"><h3>${icon('coin')} Budgets</h3><span class="muted">enterprise billing</span></div>
      ${budgets.length ? `<div class="budgets">${budgets.map((b) => `<div class="budget ${b.alerting || b.prevent ? '' : 'weak'}">
        <div class="b-ic">${icon(scopeIcon[b.scope] || 'coin')}</div>
        <div class="b-body"><b>${esc(b.entity || '—')}</b><small>${esc(b.scope.replace(/_/g, ' '))}${b.type ? ` · ${esc(b.type)}` : ''}${b.sku ? ` · ${esc(b.sku)}` : ''}</small></div>
        <div class="b-amt">${fmtMoney(b.amount)}</div>
        <div class="b-flags"><span class="flag ${b.alerting ? 'on' : 'off'}" data-tip="${esc(b.alerting ? `Alerts ${b.recipients.length} recipient(s)` : 'No alerting')}">${icon(b.alerting ? 'check' : 'x')} Alerts</span>
          <span class="flag ${b.prevent ? 'on' : 'off'}" data-tip="${b.prevent ? 'Usage stops at the limit' : 'Spend can continue past the limit'}">${icon(b.prevent ? 'check' : 'x')} Hard cap</span></div>
      </div>`).join('')}</div>` : `<div class="empty-state">${m.enterprise?.budgetsAvailable ? 'No budgets are configured.' : 'Budget data was not available in this report.'}</div>`}
    </div>
    <div class="card reveal">
      <div class="card-head"><h3>${icon('list')} GHQR findings</h3></div>
      <div class="flist">${[...budFindings, ...cpFindings].map((g) => `<div class="frow sev-l-${g.severity}">${sevPill(g.severity)}<div><b>${esc(g.title)}</b><small>${esc(g.recommendation)}</small><small class="muted">${plural(g.items.length, SCOPE_LABEL[g.scope].toLowerCase())}</small></div></div>`).join('') || '<div class="empty-state">No Copilot or budget findings.</div>'}</div>
    </div>
  </section>`;
}

/* ─── View: Roadmap & what-if simulator ───────────────────────────────── */
const PHASES = [
  { id: 'now', title: 'Days 0–30', sub: 'Fix now', icon: 'alert', blurb: 'Critical and high-severity gaps.' },
  { id: 'next', title: 'Days 31–60', sub: 'Strengthen', icon: 'shield', blurb: 'Medium-severity governance gaps.' },
  { id: 'later', title: 'Days 61–90', sub: 'Optimise', icon: 'sparkles', blurb: 'Low-severity hygiene and polish.' },
];

function renderRoadmap(m) {
  const items = m.controls.filter((c) => c.uplift > 0.05);
  const allFixed = scoreControls(m.scored, new Set(items.map((c) => c.id)));
  const now30 = scoreControls(m.scored, new Set(items.filter((c) => c.phase === 'now').map((c) => c.id)));
  const infos = m.groups.filter((g) => g.severity === 'info' && !g.positive && g.scope !== 'repo');
  const asCode = m.repos.find((r) => /as-code|as_code|iac/i.test(r.name) && !r.archived);
  const effortLabel = { S: 'Small', M: 'Medium', L: 'Large' };

  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('road')} Roadmap</div>
    <h2>From <span class="grad-text">${fmtScore(m.overall)}</span> to <span class="grad-text">${fmtScore(now30)}</span> in 30 days</h2>
    <p>A phased 90-day plan built from the control gaps and ordered by score uplift. The first 30 days close the critical and high-severity gaps; closing every gap lifts the score to ${fmtScore(allFixed)}.<span class="hint"> Toggle items to see how the score responds.</span></p></div></section>

  <section class="roadmap">
    <div class="lanes">${PHASES.map((p) => {
      const list = items.filter((c) => c.phase === p.id).sort((a, b) => b.uplift - a.uplift);
      return `<div class="lane lane-${p.id} reveal">
        <div class="lane-head"><span class="lane-ic">${icon(p.icon)}</span><div><b>${p.title}</b><small>${p.sub} · ${esc(p.blurb)}</small></div><span class="lane-up">${fmtPts(sum(list, (c) => c.uplift))}</span></div>
        ${list.map((c) => `<div class="rm-card sev-l-${c.severity}">
          <div class="rm-top">${sevPill(c.severity)}<span class="rm-up">${fmtPts(c.uplift)} pts</span>
            <label class="switch" data-tip="Include in the what-if plan"><input type="checkbox" data-whatif="${c.id}"${state.whatIf.has(c.id) ? ' checked' : ''}><span></span></label></div>
          <button class="rm-title" data-open-control="${c.id}">${esc(c.fix)}</button>
          <div class="rm-meta"><span>${icon('target')} ${esc(failPhrase(c))}</span><span>${icon('users')} ${esc(c.owner)}</span><span>${icon('bolt')} ${effortLabel[c.effort] || c.effort} effort</span></div>
          <details class="rm-how"><summary>How to roll it out</summary><p>${esc(c.action)}</p><p>${esc(c.scale)}</p>${c.learn ? `<a class="link" href="${esc(c.learn)}" target="_blank" rel="noopener noreferrer">${icon('external')} Documentation</a>` : ''}</details>
        </div>`).join('') || `<div class="empty-state">${icon('check')} Nothing in this phase.</div>`}
      </div>`;
    }).join('')}</div>

    <aside class="whatif card reveal" id="whatif">
      <div class="eyebrow">${icon('trend')} What-if simulator</div>
      <div id="whatif-body"></div>
      <div class="whatif-actions">
        <button class="btn" data-whatif-preset="now">30-day plan</button>
        <button class="btn" data-whatif-preset="all">Everything</button>
        <button class="btn btn-ghost" data-whatif-preset="none">Reset</button>
      </div>
    </aside>
  </section>

  <section class="grid-2">
    <div class="card reveal">
      <div class="card-head"><h3>${icon('info')} Governance reviews</h3><span class="muted">informational GHQR items to confirm</span></div>
      <ul class="checklist">${infos.map((g) => `<li>${icon('eye')}<div><b>${esc(g.title)}</b><small>${esc(g.recommendation)}</small><small class="muted">${plural(g.items.length, SCOPE_LABEL[g.scope].toLowerCase())}</small></div></li>`).join('') || '<li class="empty">None.</li>'}</ul>
    </div>
    <div class="card reveal callout">
      <div class="card-head"><h3>${icon('flow')} Roll out safely, at scale</h3></div>
      <ol class="steps">
        <li><b>Codify it.</b> Manage rulesets and settings as code${asCode ? ` — <code>${esc(asCode.full)}</code> already looks like your control plane` : ''} so every change is reviewed, versioned and repeatable.</li>
        <li><b>Pilot in Evaluate mode.</b> Target a pilot set of repositories with organisation rulesets in Evaluate mode to measure impact without blocking anyone.</li>
        <li><b>Enforce and verify.</b> Switch to Active once the evaluation data is clean, then re-run GHQR to confirm the score moved.</li>
      </ol>
      <p class="fine">Rollout pattern validated in the GitHub-as-Code spike (findings F-041, F-042, F-046: organisation ruleset targeting and Evaluate mode).</p>
    </div>
  </section>`;
}

function renderWhatIf(m, fromScore) {
  const host = $('#whatif-body');
  if (!host) return;
  const fixed = state.whatIf;
  const projected = scoreControls(m.scored, fixed);
  const delta = projected - m.overall;
  const b = band(projected);
  host.innerHTML = `
    <div class="wi-gauge">${gauge(projected, { size: 250, stroke: 18, zones: true, needle: true, label: fixed.size ? 'Projected health score' : 'Current health score', ghost: fixed.size ? m.overall : null, from: fromScore ?? null })}</div>
    <div class="wi-delta"><span class="band band-${b.key}">${b.label}</span><b class="${delta > 0.05 ? 'up' : ''}">${fixed.size ? `${fmtPts(delta)} pts` : 'Select actions to simulate'}</b><small>${fixed.size ? `${plural(fixed.size, 'action')} selected` : `Current score ${fmtScore(m.overall)}`}</small></div>
    <div class="wi-domains">${m.domains.map((d) => {
      const cur = d.score, proj = scoreControls(d.controls, fixed);
      return `<div class="wi-row"><span>${esc(d.title)}</span>
        <span class="wi-bar"><i class="cur" style="width:${cur == null ? 0 : cur.toFixed(1)}%"></i><i class="proj" style="width:${proj == null ? 0 : proj.toFixed(1)}%;--c:${scoreColor(proj)}"></i></span>
        <b>${fmtScore(proj)}</b>${proj - cur > 0.05 ? `<small class="up">${fmtPts(proj - cur)}</small>` : '<small></small>'}</div>`;
    }).join('')}</div>`;
  countUp(host);
}

/* ─── View: Method & data ─────────────────────────────────────────────── */
function renderAbout(m) {
  const e = m.enterprise;
  const facts = [
    ['Report generated', m.generatedAt ? m.generatedAt.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' }) : '—'],
    ['Source file', m.sourceName || '—'],
    ['Enterprise', e ? `${e.slug}${e.name && e.name !== e.slug ? ` (${e.name})` : ''}` : '—'],
    ['Enterprise created', e?.createdAt ? fmtDate(e.createdAt) : '—'],
    ['Identity model', e?.emu ? 'Enterprise Managed Users' : e ? 'Personal accounts' : '—'],
    ['Organisations', fmtInt(m.orgs.filter((o) => !o.stub).length)],
    ['Repositories', `${fmtInt(m.repos.length)} (${fmtInt(m.repos.filter((r) => r.archived).length)} archived)`],
    ['GHQR findings', fmtInt(m.findings.length)],
  ];
  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('data')} Method &amp; data</div><h2>How this dashboard reads the report</h2>
    <p>Everything here is calculated in your browser from the GHQR JSON — nothing is sent anywhere.</p></div></section>

  <section class="grid-2">
    <div class="card reveal"><div class="card-head"><h3>${icon('data')} Report</h3></div>
      <dl class="facts">${facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl></div>
    <div class="card reveal"><div class="card-head"><h3>${icon('target')} Scoring model</h3></div>
      <p>Each <b>control</b> is a yes/no test applied to every relevant enterprise, organisation, repository or budget. Its <b>result</b> is the share that pass (alert controls are weighted by each organisation’s active repositories). Domain and overall scores are severity-weighted averages of control results:</p>
      <div class="formula">score = Σ (weight × result) ÷ Σ weight × 100</div>
      <div class="weights">${['critical', 'high', 'medium', 'low'].map((s) => `<span>${sevPill(s)} weight <b>${SEV_WEIGHT[s]}</b></span>`).join('')}</div>
      <div class="weights">${BANDS.slice().reverse().map((b) => `<span><span class="band band-${b.key}">${b.label}</span> ${b.key === 'red' ? '< 60' : b.key === 'amber' ? '60–79' : '≥ 80'}</span>`).join('')}</div>
      <p class="fine">GHQR finding counts are reproduced exactly. Controls marked “Derived” are observations from the raw data that GHQR does not raise as findings. Archived repositories are excluded from repository controls.</p></div>
  </section>

  <section class="card reveal">
    <div class="card-head"><h3>${icon('list')} Controls</h3><span class="muted">${fmtInt(m.scored.length)} scored</span></div>
    <div class="table-wrap"><table class="grid-table compact">
      <thead><tr><th>Domain</th><th>Control</th><th>Severity</th><th>Scope</th><th>Source</th><th>Result</th><th></th></tr></thead>
      <tbody>${m.controls.map((c) => `<tr data-open-control="${c.id}"><td>${esc(m.domainMap.get(c.domain)?.title || '')}</td><td><b>${esc(c.title)}</b></td>
        <td>${sevPill(c.severity)}</td><td>${esc(SCOPE_LABEL[c.scope])}</td><td>${c.ghqr ? `<code>${esc(c.ghqr)}</code>` : '<span class="tag">Derived</span>'}</td>
        <td class="res"><span class="mini-bar"><i style="width:${c.rate == null ? 0 : (c.rate * 100).toFixed(1)}%;--c:${scoreColor(c.rate == null ? null : c.rate * 100)}"></i></span></td>
        <td class="nowrap"><b>${fmtPct(c.rate)}</b> <small class="muted">${c.rate == null ? 'n/a' : `${fmtInt(c.pass.length)}/${fmtInt(c.known.length)}${c.weightBy ? ' orgs · repo-weighted' : ''}`}</small></td></tr>`).join('')}</tbody>
    </table></div>
  </section>

  <section class="grid-2">
    <div class="card reveal note-card"><div class="card-head"><h3>${icon('alert')} Data notes</h3></div>
      <ul class="notes">${m.caveats.map((t) => `<li>${esc(t)}</li>`).join('')}</ul></div>
    <div class="card reveal"><div class="card-head"><h3>${icon('eye')} Verify manually</h3><span class="muted">not assessable through the API</span></div>
      <ul class="checklist small">${MANUAL_CHECKS.map(([a, w, where]) => `<li>${icon('check')}<div><b>${esc(a)}</b><small>${esc(w)}</small><small class="muted">${esc(where)}</small></div></li>`).join('')}</ul></div>
  </section>`;
}

/* ─── View: Overview ──────────────────────────────────────────────────── */
function ghqrVerdict(sev) {
  if (sev.critical) return { key: 'red', icon: 'alert', label: 'Requires immediate attention' };
  if (sev.high) return { key: 'amber', icon: 'alert', label: 'Needs attention' };
  if (sev.medium) return { key: 'amber', icon: 'info', label: 'Fair — improvements recommended' };
  return { key: 'green', icon: 'check', label: 'Healthy' };
}

function narrative(m) {
  const S = m.overall;
  const ds = m.domains.filter((d) => d.score != null).sort((a, b) => b.score - a.score);
  const strong = ds.filter((d) => d.score >= 80);
  const weak = ds.filter((d) => d.score < 60).sort((a, b) => a.score - b.score);
  const name = m.enterprise?.slug || 'This estate';
  const lower = (d) => d.title.charAt(0).toLowerCase() + d.title.slice(1);
  let headline;
  if (S == null) headline = 'Not enough data to score this estate';
  else if (S >= 80) headline = 'A well-governed estate with a few gaps to close';
  else if (S >= 60) headline = weak.length ? `Solid foundations — ${listText(weak.map(lower))} need${weak.length === 1 ? 's' : ''} urgent attention` : 'Solid foundations, with clear room to improve';
  else headline = 'Significant gaps need immediate attention';
  const gapsOf = (d) => d.controls.filter((c) => c.uplift > 0).sort((a, b) => b.uplift - a.uplift).slice(0, 2).map((c) => c.gap);
  let html = `<b>${esc(name)}</b> scores <b>${fmtScore(S)}/100</b> across <b>${m.scored.length} controls</b> in ${m.domains.length} domains. `;
  if (strong.length) html += `<b>${esc(listText(strong.map((d) => d.title)))}</b> ${strong.length > 1 ? 'are' : 'is'} strong. `;
  if (weak.length) {
    const g = gapsOf(weak[0]);
    html += `<b>${esc(weak[0].title)}</b> is the weakest area${g.length ? `, driven by ${esc(listText(g))}` : ''}. `;
  }
  html += `GHQR recorded <b>${fmtInt(m.findings.length)}</b> findings, including <b class="t-crit">${fmtInt(m.sev.critical)} critical</b> and <b class="t-high">${fmtInt(m.sev.high)} high</b>.`;
  return { headline, html };
}

function kpiTile(o) {
  return `<div class="kpi reveal ${o.tone ? `tone-${o.tone}` : ''}" ${o.attrs || ''} ${o.tip ? `data-tip="${esc(o.tip)}"` : ''}>
    <div class="kpi-top"><span class="kpi-icon">${icon(o.icon)}</span><span class="kpi-label">${esc(o.label)}</span></div>
    <div class="kpi-value" ${o.count != null ? `data-count="${o.count}" data-suffix="${esc(o.suffix || '')}"` : ''}>${esc(o.value)}</div>
    <div class="kpi-sub">${o.sub || ''}</div></div>`;
}

function domainCard(d) {
  const b = band(d.score);
  const assessed = d.controls.filter((c) => c.rate != null && c.weight);
  const met = assessed.filter((c) => c.rate >= 0.9995).length;
  const gap = d.controls.filter((c) => c.uplift > 0).sort((a, b) => b.uplift - a.uplift)[0];
  return `<button class="domain card reveal glow-${b.key}" data-open-domain="${d.id}">
    <div class="domain-top"><span class="domain-icon">${icon(d.icon)}</span><span class="band band-${b.key}">${b.label}</span></div>
    <div class="domain-gauge">${gauge(d.score, { size: 150, label: 'out of 100' })}</div>
    <div class="domain-title">${esc(d.title)}</div>
    <div class="domain-meta">${met} of ${assessed.length} controls fully met</div>
    ${gap ? `<div class="domain-gap">${icon('target')}<span>Biggest gap: ${esc(gap.gap)} <b>· ${fmtPct(gap.rate)} met</b></span></div>` : `<div class="domain-gap ok">${icon('check')}<span>Every control met</span></div>`}
  </button>`;
}

function renderOverview(m) {
  const n = narrative(m);
  const verdict = ghqrVerdict(m.sev);
  const b = band(m.overall);
  const active = m.repos.filter((r) => !r.archived);
  const A = m.alerts;
  const orgsWithCs = m.orgs.filter((o) => (o.alerts.codeScanning || 0) > 0).length;
  const recent30 = m.repos.filter((r) => r.daysSincePush != null && r.daysSincePush <= 30).length;
  const cp = m.orgs.filter((o) => o.copilot);
  const seats = sum(cp, (o) => o.copilot.seats || 0);

  const kpis = [
    { icon: 'org', label: 'Organisations', value: fmtInt(m.orgs.filter((o) => !o.stub).length), count: m.orgs.filter((o) => !o.stub).length, sub: m.enterprise ? `1 enterprise${m.enterprise.emu ? ' · EMU' : ''}` : '', attrs: 'data-goto="orgs"' },
    { icon: 'repo', label: 'Repositories', value: fmtInt(m.repos.length), count: m.repos.length, sub: `${fmtInt(active.length)} active · ${fmtInt(m.repos.length - active.length)} archived`, attrs: 'data-goto="repos"' },
    { icon: 'list', label: 'GHQR findings', value: fmtInt(m.findings.length), count: m.findings.length, sub: `<span class="t-crit">${fmtInt(m.sev.critical)} critical</span> · <span class="t-high">${fmtInt(m.sev.high)} high</span>`, attrs: 'data-goto="findings"' },
    { icon: 'bug', label: 'Dependabot', value: alertText(A.dependabot), count: A.dependabot.value, suffix: A.dependabot.maybeMore ? '+' : '', sub: `<span class="t-crit">${fmtInt(A.critical.value)} critical</span> · <span class="t-high">${fmtInt(A.high.value)} high</span> open`, tone: A.critical.value ? 'bad' : A.dependabot.value ? 'warn' : 'good', attrs: 'data-goto="security"' },
    { icon: 'eye', label: 'Code scanning', value: alertText(A.codeScanning), count: A.codeScanning.value, suffix: A.codeScanning.maybeMore ? '+' : '', sub: `open in ${plural(orgsWithCs, 'organisation')}`, tone: A.codeScanning.value ? 'warn' : 'good', attrs: 'data-goto="security"', tip: A.codeScanning.maybeMore ? 'At least one organisation reports exactly 100 — the true number may be higher.' : '' },
    { icon: 'lock', label: 'Secret scanning', value: alertText(A.secretScanning), count: A.secretScanning.value, sub: A.secretScanning.value ? 'exposed secrets to rotate' : 'none open', tone: A.secretScanning.value ? 'bad' : 'good', attrs: 'data-goto="security"' },
    { icon: 'activity', label: 'Recently active', value: fmtPct(m.repos.length ? recent30 / m.repos.length : null), count: m.repos.length ? Math.round((100 * recent30) / m.repos.length) : null, suffix: '%', sub: `${fmtInt(recent30)} of ${fmtInt(m.repos.length)} in 30 days`, tip: 'Repositories with a push in the 30 days before the report' },
    { icon: 'copilot', label: 'Copilot seats', value: fmtInt(seats), count: seats, sub: `${fmtInt(sum(cp, (o) => o.copilot.active || 0))} active this cycle`, attrs: 'data-goto="copilot"' },
  ];

  const strengths = m.strengths.slice(0, 8);
  const focus = m.focus.slice(0, 6);
  const maxUp = Math.max(0.1, ...focus.map((c) => c.uplift));

  const cats = Object.entries(m.findings.reduce((acc, f) => { (acc[f.category] ||= { total: 0, ...Object.fromEntries(SEVERITIES.map((s) => [s, 0])) }); acc[f.category][f.severity] += 1; acc[f.category].total += 1; return acc; }, {}))
    .sort((a, b) => b[1].total - a[1].total);
  const catMax = Math.max(1, ...cats.map(([, v]) => v.total));

  const byOrg = m.orgs.filter((o) => o.repos.length).sort((a, b) => b.repos.length - a.repos.length);
  const buckets = [['≤ 7 days', 0, 7], ['8–30 days', 8, 30], ['31–90 days', 31, 90], ['91–180 days', 91, 180], ['> 180 days', 181, Infinity]]
    .map(([label, lo, hi], i) => ({ label, value: m.repos.filter((r) => r.daysSincePush != null && r.daysSincePush >= lo && r.daysSincePush <= hi).length, color: `var(--seq-${i})` }));
  const langs = Object.entries(m.repos.reduce((acc, r) => { const k = r.language || 'Not detected'; acc[k] = (acc[k] || 0) + 1; return acc; }, {})).sort((a, b) => b[1] - a[1]);
  const topLangs = langs.filter(([k]) => k !== 'Not detected').slice(0, 7);
  const vis = ['INTERNAL', 'PRIVATE', 'PUBLIC'].map((v) => ({ key: v, value: m.repos.filter((r) => r.visibility === v).length }));

  return `
  <section class="hero card reveal">
    <div class="hero-glow"></div>
    <div class="hero-gauge">
      ${gauge(m.overall, { size: 300, stroke: 20, zones: true, needle: true, ticks: true, label: 'Estate health score', cls: 'hero-dial' })}
      <span class="band band-${b.key} band-lg">${b.label}</span>
    </div>
    <div class="hero-copy">
      <div class="eyebrow">${icon('activity')} Estate health review · ${esc(fmtDate(m.generatedAt))}</div>
      <h2 class="hero-title">${esc(n.headline)}</h2>
      <p class="hero-text">${n.html}</p>
      <div class="hero-chips">
        <button class="verdict verdict-${verdict.key}" data-goto="findings">${icon(verdict.icon)}<span>GHQR verdict: <b>${esc(verdict.label)}</b></span></button>
        <button class="chip-btn" data-goto="roadmap">${icon('road')}<span>Roadmap to <b>${fmtScore(scoreControls(m.scored, new Set(m.focus.filter((c) => c.phase === 'now').map((c) => c.id))))}</b> in 30 days</span></button>
        <button class="chip-btn" data-goto="about">${icon('info')}<span>How the score works</span></button>
      </div>
    </div>
    <div class="hero-sev">
      ${donut(SEVERITIES.map((s) => ({ label: SEV_LABEL[s], value: m.sev[s], color: `var(--sev-${s})`, attrs: `data-goto-sev="${s}"` })), { size: 200, stroke: 24, center: fmtInt(m.findings.length), countTo: m.findings.length, sub: 'GHQR findings', label: 'Findings by severity' })}
      <ul class="sev-legend">${SEVERITIES.map((s) => `<li><button data-goto-sev="${s}"><span class="dot" style="--c:var(--sev-${s})"></span>${SEV_LABEL[s]}<b data-count="${m.sev[s]}">${fmtInt(m.sev[s])}</b></button></li>`).join('')}</ul>
    </div>
  </section>

  <section class="kpis">${kpis.map(kpiTile).join('')}</section>

  <section class="section">
    <div class="section-head"><div><h3>${icon('target')} Posture by domain</h3><p>Each dial is the severity-weighted share of controls met.<span class="hint"> Click a dial for the controls behind it.</span></p></div>
    <div class="legend-inline"><span><i class="lg lg-red"></i>At risk &lt; 60</span><span><i class="lg lg-amber"></i>Fair 60–79</span><span><i class="lg lg-green"></i>Strong ≥ 80</span></div></div>
    <div class="domains">${m.domains.map(domainCard).join('')}</div>
  </section>

  <section class="grid-2">
    <div class="card reveal panel-strengths">
      <div class="card-head"><h3>${icon('shield')} What’s working well</h3><span class="muted">${fmtInt(m.strengths.length)} controls fully met</span></div>
      <ul class="strengths">${strengths.map((c) => `<li><button data-open-control="${c.id}"><span class="s-ic">${icon('check')}</span><span class="s-body"><b>${esc(c.title)}</b><small>${esc(passPhrase(c))}</small></span><span class="imp imp-${c.severity}">${SEV_LABEL[c.severity]} impact</span></button></li>`).join('') || '<li class="empty">No control is fully met yet.</li>'}</ul>
    </div>
    <div class="card reveal panel-focus">
      <div class="card-head"><h3>${icon('flag')} Where to focus first</h3><span class="muted">ranked by score uplift</span></div>
      <ol class="focus">${focus.map((c, i) => `<li><button data-open-control="${c.id}">
        <span class="f-rank">${i + 1}</span>
        <span class="f-body"><b>${esc(c.fix)}</b><small>${sevPill(c.severity)} ${esc(failPhrase(c))}</small></span>
        <span class="f-uplift"><span class="f-bar"><i style="--w:${((100 * c.uplift) / maxUp).toFixed(1)}%;--i:${i}"></i></span><b>${fmtPts(c.uplift)}</b><small>pts</small></span>
      </button></li>`).join('') || '<li class="empty">Nothing to fix — every control is met.</li>'}</ol>
    </div>
  </section>

  <section class="section">
    <div class="section-head"><div><h3>${icon('sparkles')} Key observations</h3><p>Patterns spotted in the raw data that are easy to miss in a findings list.<span class="hint"> Click one to see the control behind it.</span></p></div><span class="tag">Derived insight</span></div>
    <div class="insights">${m.insights.map((x) => `<div class="insight card reveal tone-${x.tone}" ${x.control ? `data-open-control="${x.control}"` : ''}><span class="i-ic">${icon(x.icon)}</span><div><b>${esc(x.title)}</b><p>${esc(x.text)}</p></div></div>`).join('')}</div>
  </section>

  <section class="card reveal">
    <div class="card-head"><div><h3>${icon('map')} Estate map</h3><p class="muted">Every repository as a tile, grouped by organisation and coloured by its health score.<span class="hint"> Hover for details, click to drill in.</span></p></div>
      <div class="tm-legend"><span>40</span><i class="tm-scale"></i><span>100</span><span class="tm-arch"><i></i>Archived</span></div></div>
    <div id="treemap" class="treemap" aria-label="Estate map"></div>
  </section>

  <section class="grid-2">
    <div class="card reveal">
      <div class="card-head"><h3>${icon('list')} Findings by category</h3><span class="muted hint">click a row to explore</span></div>
      <div class="cats">${cats.map(([k, v]) => `<button class="cat-row" data-goto-cat="${esc(k)}"><span class="cat-label">${esc(catLabel(k))}</span><span class="cat-bar" style="--w:${((100 * v.total) / catMax).toFixed(1)}%">${sevStack(v)}</span><b>${fmtInt(v.total)}</b></button>`).join('')}</div>
    </div>
    <div class="card reveal"><div class="card-head"><h3>${icon('org')} Repositories by organisation</h3><span class="muted hint">click to open</span></div>
      ${hbars(byOrg.map((o, i) => ({ label: o.login, value: o.repos.length, color: `var(--seq-${i % 6})`, attrs: `data-open-org="${esc(o.login)}"`, tip: `${o.login}: ${o.activeRepoCount} active, ${o.repos.length - o.activeRepoCount} archived` })))}</div>
  </section>

  <section class="grid-3">
    <div class="card reveal"><div class="card-head"><h3>${icon('activity')} Last push</h3><span class="muted small">days since the most recent push</span></div>${vbars(buckets)}</div>
    <div class="card reveal"><div class="card-head"><h3>${icon('repo')} Top languages</h3><span class="muted small">${fmtInt(langs.find(([k]) => k === 'Not detected')?.[1] || 0)} not detected</span></div>
      ${hbars(topLangs.map(([k, v], i) => ({ label: k, value: v, color: `var(--seq-${(i + 2) % 6})` })), { cls: 'compact' })}</div>
    <div class="card reveal center"><div class="card-head"><h3>${icon('eye')} Visibility</h3></div>
      ${donut(vis.map((v, i) => ({ label: cap(v.key.toLowerCase()), value: v.value, color: ['var(--accent)', 'var(--accent-2)', 'var(--sev-critical)'][i] })), { size: 150, stroke: 20, center: fmtInt(m.repos.length), sub: 'repositories' })}
      <div class="mini-legend">${vis.map((v, i) => `<span><i style="--c:${['var(--accent)', 'var(--accent-2)', 'var(--sev-critical)'][i]}"></i>${cap(v.key.toLowerCase())} <b>${fmtInt(v.value)}</b></span>`).join('')}</div></div>
  </section>`;
}

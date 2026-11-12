/* ─── Tabs ────────────────────────────────────────────────────────────── */
const TABS = [
  { id: 'overview', label: 'Overview', icon: 'activity', render: renderOverview },
  { id: 'security', label: 'Security', icon: 'bug', render: renderSecurity },
  { id: 'orgs', label: 'Organisations', icon: 'org', render: renderOrgs },
  { id: 'repos', label: 'Repositories', icon: 'repo', render: renderRepos },
  { id: 'findings', label: 'Findings', icon: 'list', render: renderFindings },
  { id: 'copilot', label: 'Copilot & cost', icon: 'copilot', render: renderCopilot },
  { id: 'roadmap', label: 'Roadmap', icon: 'road', render: renderRoadmap },
  { id: 'about', label: 'Method & data', icon: 'data', render: renderAbout },
];
const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ─── Drawers ─────────────────────────────────────────────────────────── */
const fact = (k, v) => `<div class="fact"><small>${esc(k)}</small><b>${esc(v)}</b></div>`;
function findingItems(list) {
  if (!list.length) return `<div class="empty-state">${icon('check')} No GHQR findings.</div>`;
  return `<div class="flist">${list.slice().sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]).map((f) => `
    <div class="frow sev-l-${f.severity}">${sevPill(f.severity)}<div><b>${esc(f.issue)}</b><small>${esc(f.recommendation)}</small>
    ${f.learnMore ? `<a class="link" href="${esc(f.learnMore)}" target="_blank" rel="noopener noreferrer">${icon('external')} Learn more</a>` : ''}</div></div>`).join('')}</div>`;
}
function controlList(results, entity) {
  return `<ul class="ctl-list">${results.slice().sort((a, b) => a.ok - b.ok || b.c.weight - a.c.weight).map(({ c, ok }) => `
    <li class="${ok ? 'ok' : 'bad'}"><button data-open-control="${c.id}">${icon(ok ? 'check' : 'x')}<span><b>${esc(c.title)}</b>${!ok && c.detail ? `<small>${esc(c.detail(entity))}</small>` : ''}</span>${sevPill(c.severity)}</button></li>`).join('')}</ul>`;
}

function repoDrawer(m, r) {
  const url = repoUrl(m, r);
  const sev = countBySeverity(r.findings);
  return `
  <div class="dw-head">
    <div class="eyebrow">${icon('repo')} Repository · <button class="link" data-open-org="${esc(r.org)}">${esc(r.org)}</button></div>
    <h2>${esc(r.name)}</h2>
    <div class="dw-chips">${r.archived ? '<span class="tag tag-muted">archived</span>' : ''}<span class="tag">${esc(r.visibility.toLowerCase())}</span>${r.language ? `<span class="tag">${esc(r.language)}</span>` : ''}${r.defaultBranch ? `<span class="tag">${icon('branch')}${esc(r.defaultBranch)}</span>` : ''}</div>
    <p class="dw-desc ${r.description ? '' : 'muted'}">${esc(r.description || 'No description.')}</p>
    ${r.topics.length ? `<div class="dw-topics">${r.topics.map((t) => `<span class="topic">${esc(t)}</span>`).join('')}</div>` : ''}
    ${url ? `<a class="btn btn-ghost small" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${icon('external')} Open on GitHub</a>` : ''}
  </div>
  <div class="dw-score">
    ${r.score == null ? `<div class="dw-archived">${icon('info')}<span>Archived repositories are read-only and not scored.</span></div>` : gauge(r.score, { size: 160, label: 'health score' })}
    <div class="dw-facts">
      ${fact('Last push', relDays(r.daysSincePush))}
      ${fact('Protection', r.isProtected ? (r.protectedBy === 'legacy' ? 'Legacy branch protection' : `${r.rulesetCount} ruleset(s)`) : 'None')}
      ${fact('Approvals required', String(r.approvals))}
      ${fact('Status checks', r.statusChecks ? `${r.contexts.length} · ${r.strictChecks ? 'strict' : 'not strict'}` : 'None')}
      ${fact('Code-owner review', r.codeOwnerReviews ? (r.codeowners ? 'Required' : 'Required · no owners') : 'Not required')}
      ${fact('GHQR findings', `${r.findings.length} · ${sev.high} high`)}
    </div>
  </div>
  ${r.contexts.length ? `<div class="dw-sec"><h4>Required checks</h4><div class="dw-topics">${r.contexts.map((x) => `<code>${esc(x)}</code>`).join('')}</div></div>` : ''}
  ${r.results.length ? `<div class="dw-sec"><h4>Controls</h4>${controlList(r.results, r)}</div>` : ''}
  <div class="dw-sec"><h4>GHQR findings (${r.findings.length})</h4>${findingItems(r.findings)}</div>`;
}

function orgDrawer(m, o) {
  const url = orgUrl(m, o);
  const results = m.controls.filter((c) => c.scope === 'org' && c.knownSet.has(o)).map((c) => ({ c, ok: c.passSet.has(o) }));
  const repos = o.repos.slice().sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  const A = o.alerts;
  const legacy = Object.entries(o.legacyDefaults || {});
  return `
  <div class="dw-head">
    <div class="eyebrow">${icon('org')} Organisation</div>
    <h2>${esc(o.login)}</h2>
    <p class="dw-desc ${o.description ? '' : 'muted'}">${esc(o.description || 'No description.')}</p>
    ${url ? `<a class="btn btn-ghost small" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${icon('external')} Open on GitHub</a>` : ''}
  </div>
  <div class="dw-score">
    ${gauge(o.score, { size: 160, label: 'health score' })}
    <div class="dw-facts">
      ${fact('Repositories', `${o.activeRepoCount} active · ${o.repos.length - o.activeRepoCount} archived`)}
      ${fact('Base permission', o.basePermission || '—')}
      ${fact('Allowed actions', o.allowedActions || '—')}
      ${fact('Workflow token', o.tokenPerm || '—')}
      ${fact('Copilot seats', o.copilot ? `${fmtInt(o.copilot.seats)} (${o.copilot.seatMgmt || '—'})` : '—')}
      ${fact('GHQR findings', `${o.findings.length} org · ${sum(o.repos, (r) => r.findings.length)} repo`)}
    </div>
  </div>
  <div class="dw-sec"><h4>Open alerts</h4><div class="dw-alerts">
    ${[['Critical', A.critical, 'critical'], ['High', A.high, 'high'], ['Dependabot', A.dependabot, 'medium'], ['Code scanning', A.codeScanning, 'high'], ['Secrets', A.secretScanning, 'critical']]
      .map(([l, v, s]) => `<div class="dw-alert ${v ? `on sev-bg-${s}` : ''}"><b>${v == null ? '—' : `${fmtInt(v)}${v === 100 ? '+' : ''}`}</b><small>${l}</small></div>`).join('')}</div></div>
  ${results.length ? `<div class="dw-sec"><h4>Organisation controls</h4>${controlList(results, o)}</div>` : ''}
  <div class="dw-sec"><h4>Repositories (${repos.length})</h4><div class="mini-repos">${repos.map((r) => `
    <button data-open-repo="${esc(r.full)}"><span class="score-pill sm" style="--c:${scoreColor(r.score)}">${r.score == null ? '—' : fmtScore(r.score)}</span><b>${esc(r.name)}</b>${r.archived ? '<span class="tag tag-muted">archived</span>' : ''}<small>${r.failing.length ? `${r.failing.length} gaps` : ''}</small></button>`).join('')}</div></div>
  <div class="dw-sec"><h4>GHQR findings (${o.findings.length})</h4>${findingItems(o.findings)}</div>
  ${legacy.length ? `<details class="dw-sec legacy"><summary>Legacy “new repository” defaults (deprecated API fields — reference only)</summary>
    <ul class="kv">${legacy.map(([k, v]) => `<li><span>${esc(k.replace(/_/g, ' '))}</span><b>${esc(String(v))}</b></li>`).join('')}</ul></details>` : ''}`;
}

function controlDrawer(m, c) {
  const d = m.domainMap.get(c.domain);
  const openAttr = (e) => (c.scope === 'repo' ? `data-open-repo="${esc(e.full)}"` : c.scope === 'org' ? `data-open-org="${esc(e.login)}"` : '');
  const entRow = (e, ok) => `<button class="ent ${ok ? 'ok' : 'bad'}" ${openAttr(e)}>${icon(ok ? 'check' : 'x')}<b>${esc(entityName(c.scope, e))}</b>${!ok && c.detail ? `<small>${esc(c.detail(e))}</small>` : ''}${!ok && c.alertKey ? `<small>${fmtInt(e.alerts[c.alertKey])}${e.alerts[c.alertKey] === 100 ? '+' : ''} open</small>` : ''}</button>`;
  return `
  <div class="dw-head">
    <div class="eyebrow">${icon(d?.icon || 'target')} ${esc(d?.title || '')} · control</div>
    <h2>${esc(c.title)}</h2>
    <div class="dw-chips">${sevPill(c.severity)}<span class="tag">${esc(SCOPE_LABEL[c.scope])}</span>${c.ghqr ? `<span class="tag"><code>${esc(c.ghqr)}</code></span>` : '<span class="tag">Derived</span>'}</div>
  </div>
  <div class="dw-score">
    ${ring(c.rate, { size: 140, label: c.title })}
    <div class="dw-facts">
      ${fact('Meeting the control', c.rate == null ? 'Not assessed' : passPhrase(c))}
      ${fact('Gap', c.fail.length ? failPhrase(c) : 'None')}
      ${fact('Score uplift if fixed', c.uplift > 0.05 ? `${fmtPts(c.uplift)} pts overall` : '—')}
      ${fact('Suggested owner', c.owner)}
    </div>
  </div>
  <div class="dw-sec prose"><h4>Why it matters</h4><p>${esc(c.why)}</p>
    <h4>What to do</h4><p>${esc(c.action)}</p>
    <h4>How to roll it out</h4><p>${esc(c.scale)}</p>
    ${c.note ? `<p class="callout-inline">${icon('info')}<span>${esc(c.note)}</span></p>` : ''}
    ${c.relatedArchived.length ? `<p class="callout-inline">${icon('info')}<span>GHQR also raised this on ${plural(c.relatedArchived.length, 'archived repository', 'archived repositories')}, which are excluded from scoring.</span></p>` : ''}
    ${c.learn ? `<a class="link" href="${esc(c.learn)}" target="_blank" rel="noopener noreferrer">${icon('external')} GitHub documentation</a>` : ''}
  </div>
  ${c.scope === 'repo' && c.fail.length && !c.allRepos ? `<div class="dw-sec"><button class="btn btn-primary" data-filter-control="${c.id}">${icon('repo')} Show these repositories in the explorer</button></div>` : ''}
  ${c.fail.length ? `<div class="dw-sec"><h4>Not meeting the control (${fmtInt(c.fail.length)})</h4><div class="ents">${c.fail.slice(0, 250).map((e) => entRow(e, false)).join('')}</div></div>` : ''}
  ${c.pass.length ? `<details class="dw-sec"><summary>Meeting the control (${fmtInt(c.pass.length)})</summary><div class="ents">${c.pass.slice(0, 250).map((e) => entRow(e, true)).join('')}</div></details>` : ''}`;
}

function domainDrawer(m, d) {
  const cs = d.controls.slice().sort((a, b) => (a.rate ?? 2) - (b.rate ?? 2) || b.weight - a.weight);
  return `
  <div class="dw-head"><div class="eyebrow">${icon(d.icon)} Domain</div><h2>${esc(d.title)}</h2><p class="dw-desc">${esc(d.blurb)}</p></div>
  <div class="dw-score">${gauge(d.score, { size: 170, label: band(d.score).label })}
    <div class="dw-facts">${fact('Controls assessed', String(cs.filter((c) => c.rate != null).length))}${fact('Fully met', String(cs.filter((c) => c.rate != null && c.rate >= 0.9995).length))}
    ${fact('Uplift if all fixed', `${fmtPts(scoreControls(m.scored, new Set(cs.map((c) => c.id))) - m.overall)} pts overall`)}</div></div>
  <div class="dw-sec"><h4>Controls</h4><div class="dom-controls">${cs.map((c) => `
    <button class="dc" data-open-control="${c.id}"><span class="dc-top"><b>${esc(c.title)}</b>${sevPill(c.severity)}</span>
      <span class="dc-bar"><i style="width:${c.rate == null ? 0 : (c.rate * 100).toFixed(1)}%;--c:${scoreColor(c.rate == null ? null : c.rate * 100)}"></i></span>
      <small>${esc(c.rate == null ? 'Not assessed' : `${fmtPct(c.rate)} · ${c.fail.length ? failPhrase(c) : passPhrase(c)}`)}</small></button>`).join('')}</div></div>
  <div class="dw-sec"><button class="btn btn-primary" data-goto="${d.tab}">${icon('chevron')} Go to ${esc(TABS.find((t) => t.id === d.tab)?.label || '')}</button></div>`;
}

let lastFocus = null;
function openDrawer(html) {
  const dr = $('#drawer');
  lastFocus = document.activeElement;
  $('#drawer-body').innerHTML = html;
  dr.classList.add('open');
  dr.setAttribute('aria-hidden', 'false');
  $('#scrim').classList.add('on');
  $('#drawer-body').scrollTop = 0;
  animatePanel(dr);
  setTimeout(() => $('#drawer-close').focus({ preventScroll: true }), 50);
}
function closeDrawer() {
  const dr = $('#drawer');
  if (!dr.classList.contains('open')) return false;
  dr.classList.remove('open');
  dr.setAttribute('aria-hidden', 'true');
  $('#scrim').classList.remove('on');
  if (lastFocus && document.contains(lastFocus)) lastFocus.focus({ preventScroll: true });
  return true;
}

/* ─── Rendering orchestration ─────────────────────────────────────────── */
function renderHeader(m) {
  const e = m.enterprise;
  const title = e?.slug || (m.orgs.length === 1 ? m.orgs[0].login : 'GitHub estate');
  $('#hdr-title').textContent = title;
  document.title = `${title} · GitHub estate health`;
  const chips = [];
  if (e?.emu) chips.push(`<span class="hchip" data-tip="Enterprise Managed Users">${icon('key')}EMU</span>`);
  try {
    if (m.webBase && /\.ghe\.com$/i.test(new URL(m.webBase).hostname)) chips.push(`<span class="hchip" data-tip="GitHub Enterprise Cloud with data residency">${icon('shield')}GHE.com</span>`);
  } catch { /* ignore malformed URLs */ }
  $('#hdr-chips').innerHTML = chips.join('');
  $('#hdr-meta').innerHTML = [
    `Generated ${fmtDate(m.generatedAt)}`,
    plural(m.orgs.filter((o) => !o.stub).length, 'organisation'),
    plural(m.repos.length, 'repository', 'repositories'),
    `${fmtInt(m.findings.length)} GHQR findings`,
  ].map(esc).join('<span class="sep"></span>');
  $('#print-foot').innerHTML = `<span>${esc(title)} · GitHub estate health review</span><span>GHQR report generated ${esc(fmtDate(m.generatedAt))} · Confidential</span>`;
  $('#tabs').innerHTML = `${TABS.map((t, i) => `<button role="tab" id="tab-${t.id}" data-tab="${t.id}" aria-controls="panel-${t.id}" data-key="${i + 1}">${icon(t.icon)}<span>${esc(t.label)}</span></button>`).join('')}<span class="tab-ink" id="tab-ink"></span>`;
  $('#tabs').hidden = false;
  $$('#btn-unload, #btn-present, #btn-export').forEach((b) => { b.hidden = false; });
}

function resetReportState(model = null) {
  state.model = model;
  orgCtx = null;
  state.tab = 'overview';
  state.whatIf = new Set();
  state.repo = { q: '', org: '', control: '', band: '', archived: false, sort: 'score', dir: 1 };
  state.finding = { q: '', sev: new Set(SEVERITIES), scope: '', category: '' };
}

function renderAll(m) {
  closeDrawer();
  $('#drawer-body').replaceChildren();
  lastFocus = null;
  resetReportState(m);
  renderHeader(m);
  $('#app').innerHTML = TABS.map((t) => `<section class="panel" id="panel-${t.id}" role="tabpanel" aria-labelledby="tab-${t.id}" hidden>${t.render(m)}</section>`).join('');
  renderRepoTable(m);
  renderFindingList(m);
  renderWhatIf(m);
  const hash = location.hash.slice(1);
  showTab(TABS.some((t) => t.id === hash) ? hash : 'overview', false);
}

function showTab(id, scroll = true) {
  if (!TABS.some((t) => t.id === id)) id = 'overview';
  state.tab = id;
  for (const p of $$('.panel')) p.hidden = p.id !== `panel-${id}`;
  for (const b of $$('#tabs [data-tab]')) {
    const on = b.dataset.tab === id;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  }
  if (location.hash.slice(1) !== id) history.replaceState(null, '', `#${id}`);
  moveInk();
  animatePanel($(`#panel-${id}`));
  if (id === 'overview') renderTreemap(state.model);
  if (scroll) window.scrollTo({ top: 0, behavior: reducedMotion() ? 'auto' : 'smooth' });
  $('#present-counter').textContent = `${TABS.findIndex((t) => t.id === id) + 1} / ${TABS.length} · ${TABS.find((t) => t.id === id).label}`;
}
function stepTab(delta) {
  const i = TABS.findIndex((t) => t.id === state.tab);
  showTab(TABS[(i + delta + TABS.length) % TABS.length].id);
}
function moveInk() {
  const b = $('#tabs .active');
  const ink = $('#tab-ink');
  if (!b || !ink) return;
  ink.style.width = `${b.offsetWidth}px`;
  ink.style.transform = `translateX(${b.offsetLeft}px)`;
}

function animatePanel(root) {
  if (!root) return;
  if (reducedMotion()) { countUp(root); return; }
  root.classList.remove('animate');
  $$('.reveal', root).forEach((el, i) => el.style.setProperty('--d', Math.min(i, 14)));
  void root.offsetWidth;
  root.classList.add('animate');
  countUp(root);
}

function countUp(root) {
  const items = $$('[data-count]', root).filter((el) => el.dataset.count !== '' && !Number.isNaN(Number(el.dataset.count)))
    .map((el) => ({ el, to: Number(el.dataset.count), from: Number(el.dataset.from || 0), suffix: el.dataset.suffix || '' }));
  const paint = (p) => { for (const it of items) it.el.textContent = `${fmtInt(it.from + (it.to - it.from) * p)}${it.suffix}`; };
  if (!items.length) return;
  if (reducedMotion() || document.visibilityState !== 'visible' || document.body.classList.contains('print-prep')) { paint(1); return; }
  paint(0);
  const t0 = performance.now();
  const dur = 1200;
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    paint(1 - (1 - p) ** 3);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* ─── Tooltip ─────────────────────────────────────────────────────────── */
const tipEl = () => $('#tooltip');
function placeTip(e) {
  const t = tipEl();
  const pad = 14;
  const w = t.offsetWidth, h = t.offsetHeight;
  let x = e.clientX + pad, y = e.clientY + pad;
  if (x + w > window.innerWidth - 8) x = e.clientX - w - pad;
  if (y + h > window.innerHeight - 8) y = e.clientY - h - pad;
  t.style.transform = `translate(${Math.max(8, x)}px, ${Math.max(8, y)}px)`;
}

/* ─── Loading reports ─────────────────────────────────────────────────── */
function toast(msg, tone = 'bad') {
  const t = $('#toast');
  t.className = `toast on tone-${tone}`;
  t.textContent = msg;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = 'toast'; }, 6000);
}
function load(raw, name) {
  try {
    renderAll(analyse(raw, name));
  } catch (err) {
    console.error(err);
    toast(`Could not read this report: ${err.message}`);
    if (!state.model) showLanding();
  }
}
let reportReader = null;
function loadFile(file) {
  if (!file) return;
  reportReader?.abort();
  const reader = new FileReader();
  reportReader = reader;
  reader.onload = () => {
    if (reportReader !== reader) return;
    reportReader = null;
    try { load(JSON.parse(String(reader.result)), file.name); } catch (err) { toast(`That file is not valid JSON: ${err.message}`); }
  };
  reader.onerror = () => {
    if (reportReader !== reader) return;
    reportReader = null;
    toast(`Could not read this file: ${reader.error?.message || 'Unknown file error.'}`);
  };
  reader.readAsText(file);
}
function showLanding() {
  reportReader?.abort();
  reportReader = null;
  closeDrawer();
  $('#drawer-body').replaceChildren();
  lastFocus = null;
  if (document.body.classList.contains('present')) togglePresent(false);
  document.body.classList.remove('print-prep');
  printState.active = false;
  printState.opened = [];
  printState.whatIfPreset = false;
  resetReportState();
  $('#tabs').hidden = true;
  $('#tabs').replaceChildren();
  $$('#btn-unload, #btn-present, #btn-export').forEach((b) => { b.hidden = true; });
  document.title = 'GitHub estate health';
  $('#hdr-title').textContent = 'GitHub estate health';
  $('#hdr-chips').replaceChildren();
  $('#hdr-meta').textContent = 'Load a GHQR JSON report to begin';
  $('#print-foot').replaceChildren();
  $('#present-counter').textContent = '';
  tipEl().classList.remove('on');
  tipEl().textContent = '';
  $('#ghqr-data').textContent = 'null';
  $('#ghqr-data').removeAttribute('data-source');
  $('#file-input').value = '';
  if (location.hash) history.replaceState(null, '', `${location.pathname}${location.search}`);
  $('#app').innerHTML = `<section class="landing card" tabindex="-1"><div class="landing-ic">${icon('upload')}</div><h2>Drop a GHQR JSON report here</h2>
    <p>Or choose a file. Everything runs locally in your browser — no data leaves this machine.</p>
    <label class="btn btn-primary">${icon('upload')} Choose report<input type="file" accept=".json,application/json" data-file hidden></label></section>`;
}

/* ─── Theme & presentation ────────────────────────────────────────────── */
function applyTheme(t, persist = true) {
  document.documentElement.dataset.theme = t;
  const b = $('#btn-theme');
  if (b) b.innerHTML = `${icon(t === 'dark' ? 'sun' : 'moon')}<span>${t === 'dark' ? 'Light' : 'Dark'}</span>`;
  if (persist) try { localStorage.setItem('ghqr-theme', t); } catch { /* storage unavailable */ }
}
function togglePresent(force) {
  const on = force ?? !document.body.classList.contains('present');
  document.body.classList.toggle('present', on);
  if (on && document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
  if (!on && document.fullscreenElement) document.exitFullscreen().catch(() => {});
  setTimeout(() => { moveInk(); if (state.model && state.tab === 'overview') renderTreemap(state.model); }, 250);
}

/* ─── PDF export: print the whole dashboard, every section expanded ───── */
const QUERY = new URLSearchParams(location.search);
const EXPORT_MODE = QUERY.get('export') === 'pdf';
const printState = { active: false, opened: [], whatIfPreset: false };

function finishCounts(root = document) {
  for (const el of $$('[data-count]', root)) {
    const to = Number(el.dataset.count);
    if (el.dataset.count === '' || Number.isNaN(to)) continue;
    el.textContent = `${fmtInt(to)}${el.dataset.suffix || ''}`;
  }
}
function setWhatIf(m, preset, animateFrom = null) {
  const cand = m.controls.filter((c) => c.uplift > 0.05);
  state.whatIf = new Set(preset === 'all' ? cand.map((c) => c.id) : preset === 'now' ? cand.filter((c) => c.phase === 'now').map((c) => c.id) : []);
  $$('[data-whatif]').forEach((x) => { x.checked = state.whatIf.has(x.dataset.whatif); });
  renderWhatIf(m, animateFrom);
}
function preparePrint() {
  const m = state.model;
  if (!m || printState.active) return;
  printState.active = true;
  closeDrawer();
  document.body.classList.add('print-prep');
  printState.opened = $$('#app details:not([open])');
  printState.opened.forEach((d) => { d.open = true; });
  // A static page can't be toggled, so show the 30-day plan unless the presenter chose their own scenario.
  printState.whatIfPreset = !state.whatIf.size;
  if (printState.whatIfPreset) setWhatIf(m, 'now');
  finishCounts();
  renderTreemap(m);
}
function restoreAfterPrint() {
  const m = state.model;
  if (!printState.active || EXPORT_MODE) return;
  printState.active = false;
  document.body.classList.remove('print-prep');
  printState.opened.forEach((d) => { d.open = false; });
  printState.opened = [];
  if (printState.whatIfPreset) setWhatIf(m, 'none');
  printState.whatIfPreset = false;
  moveInk();
  if (state.tab === 'overview') renderTreemap(m);
}
function exportPdf() {
  if (!state.model) return;
  toast('In the print dialog, choose “Save as PDF” as the destination.', 'info');
  setTimeout(() => window.print(), 80);
}

/* ─── Global event wiring ─────────────────────────────────────────────── */
function bindGlobal() {
  document.addEventListener('click', (e) => {
    if (e.target.closest('#drawer-close') || e.target.id === 'scrim') { closeDrawer(); return; }
    const m = state.model;
    const t = e.target.closest('[data-tab],[data-open-repo],[data-open-org],[data-open-control],[data-open-domain],[data-goto],[data-goto-sev],[data-goto-cat],[data-filter-control],[data-whatif-preset],[data-sort],[data-sev]');
    if (!t || !m || e.target.closest('a[href], summary, label.switch, input, select')) return;
    const d = t.dataset;
    if (d.tab) { showTab(d.tab); return; }
    if (d.openRepo) { const r = m.repoMap.get(d.openRepo); if (r) openDrawer(repoDrawer(m, r)); return; }
    if (d.openOrg) { const o = m.orgMap.get(d.openOrg); if (o) openDrawer(orgDrawer(m, o)); return; }
    if (d.openControl) { const c = m.controlMap.get(d.openControl); if (c) openDrawer(controlDrawer(m, c)); return; }
    if (d.openDomain) { const dm = m.domainMap.get(d.openDomain); if (dm) openDrawer(domainDrawer(m, dm)); return; }
    if (d.goto) { closeDrawer(); showTab(d.goto); return; }
    if (d.gotoSev) { state.finding = { q: '', sev: new Set([d.gotoSev]), scope: '', category: '' }; $('#find-q').value = ''; renderFindingList(m); showTab('findings'); return; }
    if (d.gotoCat) { state.finding = { q: '', sev: new Set(SEVERITIES), scope: '', category: d.gotoCat }; $('#find-q').value = ''; renderFindingList(m); showTab('findings'); return; }
    if (d.filterControl) {
      closeDrawer();
      Object.assign(state.repo, { control: d.filterControl, org: '', band: '', q: '', archived: false });
      $('#repo-control').value = d.filterControl; $('#repo-org').value = ''; $('#repo-q').value = ''; $('#repo-archived').checked = false;
      renderRepoTable(m);
      if (state.tab !== 'repos') showTab('repos', false);
      setTimeout(() => $('#repo-explorer').scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' }), 60);
      return;
    }
    if (d.whatifPreset) { setWhatIf(m, d.whatifPreset, scoreControls(m.scored, state.whatIf)); return; }
    if (d.sort) { state.repo.dir = state.repo.sort === d.sort ? -state.repo.dir : 1; state.repo.sort = d.sort; renderRepoTable(m); return; }
    if (d.sev) {
      const s = state.finding.sev;
      if (s.size === SEVERITIES.length) { s.clear(); s.add(d.sev); } else if (s.has(d.sev)) { s.delete(d.sev); if (!s.size) SEVERITIES.forEach((x) => s.add(x)); } else s.add(d.sev);
      renderFindingList(m);
    }
  });

  document.addEventListener('input', (e) => {
    const m = state.model;
    if (!m) return;
    if (e.target.id === 'repo-q') { state.repo.q = e.target.value; renderRepoTable(m); }
    if (e.target.id === 'find-q') { state.finding.q = e.target.value; renderFindingList(m); }
  });

  document.addEventListener('change', (e) => {
    const m = state.model;
    const id = e.target.id;
    if (e.target.matches('[data-file]') || id === 'file-input') { loadFile(e.target.files[0]); e.target.value = ''; return; }
    if (!m) return;
    if (id === 'repo-org') state.repo.org = e.target.value;
    else if (id === 'repo-control') state.repo.control = e.target.value;
    else if (id === 'repo-band') state.repo.band = e.target.value;
    else if (id === 'repo-archived') state.repo.archived = e.target.checked;
    else if (id === 'find-scope') { state.finding.scope = e.target.value; renderFindingList(m); return; }
    else if (id === 'find-cat') { state.finding.category = e.target.value; renderFindingList(m); return; }
    else if (e.target.dataset.whatif) {
      const before = scoreControls(m.scored, state.whatIf);
      if (e.target.checked) state.whatIf.add(e.target.dataset.whatif); else state.whatIf.delete(e.target.dataset.whatif);
      renderWhatIf(m, before);
      return;
    } else return;
    renderRepoTable(m);
  });

  document.addEventListener('click', (e) => {
    const m = state.model;
    if (!m) return;
    if (e.target.closest('#repo-csv')) exportRepos(m);
    else if (e.target.closest('#find-csv')) exportFindings(m);
    else if (e.target.closest('#repo-reset')) {
      state.repo = { q: '', org: '', control: '', band: '', archived: false, sort: 'score', dir: 1 };
      $('#repo-q').value = ''; $('#repo-org').value = ''; $('#repo-control').value = ''; $('#repo-archived').checked = false;
      renderRepoTable(m);
    }
  });

  document.addEventListener('mouseover', (e) => {
    const t = e.target.closest('[data-tip]');
    const tip = tipEl();
    if (!t || !t.dataset.tip) { tip.classList.remove('on'); return; }
    tip.textContent = t.dataset.tip;
    tip.classList.add('on');
    placeTip(e);
  });
  document.addEventListener('mousemove', (e) => { if (tipEl().classList.contains('on')) placeTip(e); });
  document.addEventListener('scroll', () => tipEl().classList.remove('on'), { passive: true });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { if (!closeDrawer() && document.body.classList.contains('present')) togglePresent(false); return; }
    const typing = e.target.closest('input, select, textarea, [contenteditable]');
    if (typing || e.altKey || e.ctrlKey || e.metaKey || !state.model || $('#drawer').classList.contains('open')) return;
    if (['ArrowRight', 'PageDown'].includes(e.key)) { e.preventDefault(); stepTab(1); }
    else if (['ArrowLeft', 'PageUp'].includes(e.key)) { e.preventDefault(); stepTab(-1); }
    else if (/^[1-8]$/.test(e.key)) showTab(TABS[Number(e.key) - 1].id);
    else if (e.key.toLowerCase() === 'p') togglePresent();
  });

  document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement) document.body.classList.remove('present'); setTimeout(moveInk, 100); });

  let rz;
  window.addEventListener('resize', () => {
    clearTimeout(rz);
    rz = setTimeout(() => { moveInk(); if (state.model && state.tab === 'overview' && !printState.active) renderTreemap(state.model); }, 150);
  });
  window.addEventListener('beforeprint', preparePrint);
  window.addEventListener('afterprint', restoreAfterPrint);

  $('#btn-theme').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('#btn-unload').addEventListener('click', () => {
    showLanding();
    window.scrollTo(0, 0);
    $('#app .landing').focus({ preventScroll: true });
    toast('Report unloaded.', 'info');
  });
  $('#btn-present').addEventListener('click', () => togglePresent());
  $('#btn-export').addEventListener('click', exportPdf);

  let depth = 0;
  window.addEventListener('dragenter', (e) => { if ([...(e.dataTransfer?.types || [])].includes('Files')) { depth += 1; $('#dropzone').classList.add('on'); } });
  window.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) $('#dropzone').classList.remove('on'); });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    depth = 0;
    $('#dropzone').classList.remove('on');
    loadFile(e.dataTransfer?.files?.[0]);
  });
}

/* ─── Boot ────────────────────────────────────────────────────────────── */
function boot() {
  document.documentElement.classList.add('booted');
  let theme = 'dark';
  try { theme = localStorage.getItem('ghqr-theme') || 'dark'; } catch { /* storage unavailable */ }
  const forced = ['dark', 'light'].includes(QUERY.get('theme')) ? QUERY.get('theme') : null;
  applyTheme(forced || theme, !forced);
  if (EXPORT_MODE) document.body.classList.add('print-prep');
  $('#btn-present').innerHTML = `${icon('expand')}<span>Present</span>`;
  $('#btn-export').innerHTML = `${icon('download')}<span>Export PDF</span>`;
  $('#btn-unload').innerHTML = `${icon('close')}<span>Unload report</span>`;
  $('#btn-load').insertAdjacentHTML('afterbegin', icon('upload'));
  $('#drawer-close').innerHTML = icon('close');
  bindGlobal();
  const el = $('#ghqr-data');
  let raw = null;
  try { raw = JSON.parse(el.textContent || 'null'); } catch { raw = null; }
  if (raw) load(raw, el.dataset.source || 'Embedded report');
  else showLanding();
  if (EXPORT_MODE) preparePrint();
}
boot();

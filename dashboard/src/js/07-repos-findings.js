/* ─── Shared UI state ─────────────────────────────────────────────────── */
const state = {
  model: null,
  tab: 'overview',
  repo: { q: '', org: '', control: '', band: '', archived: false, sort: 'score', dir: 1 },
  finding: { q: '', sev: new Set(SEVERITIES), scope: '', category: '' },
  whatIf: new Set(),
};

const yes = (ok, tip) => `<span class="yn ${ok ? 'y' : 'n'}" data-tip="${esc(tip)}">${icon(ok ? 'check' : 'x')}</span>`;

/* ─── View: Repositories ──────────────────────────────────────────────── */
function renderRepos(m) {
  const repoControls = m.controls.filter((c) => c.scope === 'repo' && c.rate != null && !c.allRepos).sort((a, b) => a.rate - b.rate);
  const orgs = m.orgs.filter((o) => o.repos.length).map((o) => o.login).sort();
  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('repo')} Repositories</div><h2>Every repository, every control</h2>
    <p>Coverage of repository-level controls across ${plural(m.repos.filter((r) => !r.archived).length, 'active repository', 'active repositories')}.<span class="hint"> Click a bar to list the repositories that miss it.</span></p></div></section>

  <section class="card reveal">
    <div class="card-head"><h3>${icon('shield')} Control coverage</h3><span class="muted">share of active repositories meeting each control</span></div>
    <div class="coverage">${repoControls.map((c, i) => `
      <button class="cov-row" data-filter-control="${c.id}" data-tip="${esc(`${c.title}\n${passPhrase(c)} · ${c.source}`)}">
        <span class="cov-label">${esc(c.title)}</span>
        <span class="cov-track"><span class="cov-fill" style="--w:${(c.rate * 100).toFixed(1)}%;--c:${scoreColor(c.rate * 100)};--i:${i}"></span></span>
        <b class="cov-val" style="color:${scoreColor(c.rate * 100)}">${fmtPct(c.rate)}</b>
        <small class="cov-n">${fmtInt(c.pass.length)}/${fmtInt(c.known.length)}</small>
        ${sevPill(c.severity)}
      </button>`).join('')}</div>
  </section>

  <section class="card reveal" id="repo-explorer">
    <div class="toolbar">
      <label class="search">${icon('search')}<input type="search" id="repo-q" placeholder="Search repositories, languages, branches…" value="${esc(state.repo.q)}"></label>
      <select id="repo-org" aria-label="Organisation"><option value="">All organisations</option>${orgs.map((o) => `<option value="${esc(o)}"${state.repo.org === o ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>
      <select id="repo-control" aria-label="Failing control"><option value="">Any control</option>${repoControls.filter((c) => c.fail.length).map((c) => `<option value="${c.id}"${state.repo.control === c.id ? ' selected' : ''}>Missing: ${esc(c.title)}</option>`).join('')}</select>
      <select id="repo-band" aria-label="Health band"><option value="">All health bands</option><option value="red">At risk (&lt; 60)</option><option value="amber">Fair (60–79)</option><option value="green">Strong (≥ 80)</option></select>
      <label class="toggle"><input type="checkbox" id="repo-archived"${state.repo.archived ? ' checked' : ''}><span></span>Include archived</label>
      <span class="grow"></span>
      <span class="muted" id="repo-count"></span>
      <button class="btn" id="repo-reset">Reset</button>
      <button class="btn btn-primary" id="repo-csv">${icon('download')} CSV</button>
    </div>
    <div class="table-wrap tall"><table class="grid-table" id="repo-table">
      <thead><tr>
        <th data-sort="name">Repository</th><th data-sort="score">Health</th><th data-sort="findings">Findings</th>
        <th data-sort="rulesets" data-tip="Rulesets applying to the default branch">Rulesets</th><th data-tip="Required status checks (strict)">CI checks</th>
        <th data-sort="approvals">Approvals</th><th>Signed</th><th>CODEOWNERS</th><th>Dependabot</th><th>dependabot.yml</th><th>Description</th>
        <th>Default branch</th><th data-sort="pushed">Last push</th>
      </tr></thead>
      <tbody id="repo-tbody"></tbody>
    </table></div>
  </section>`;
}

function filteredRepos(m) {
  const f = state.repo;
  const q = f.q.trim().toLowerCase();
  const c = f.control ? m.controlMap.get(f.control) : null;
  let list = m.repos.filter((r) => (f.archived || !r.archived)
    && (!f.org || r.org === f.org)
    && (!c || (c.knownSet.has(r) && !c.passSet.has(r)))
    && (!f.band || (r.score != null && band(r.score).key === f.band))
    && (!q || [r.full, r.description, r.language, r.defaultBranch, ...r.topics].some((x) => String(x || '').toLowerCase().includes(q))));
  const w = (r) => sum(r.findings, (x) => SEV_WEIGHT[x.severity]);
  const key = {
    name: (r) => r.full.toLowerCase(), score: (r) => (r.score == null ? 999 : r.score), findings: (r) => -w(r),
    rulesets: (r) => -r.rulesetCount, approvals: (r) => -r.approvals, pushed: (r) => (r.daysSincePush == null ? 1e9 : r.daysSincePush),
  }[f.sort] || ((r) => r.score);
  list = list.sort((a, b) => {
    const x = key(a), y = key(b);
    return (x < y ? -1 : x > y ? 1 : a.full.localeCompare(b.full)) * f.dir;
  });
  return list;
}

function renderRepoTable(m) {
  const tbody = $('#repo-tbody');
  if (!tbody) return;
  const list = filteredRepos(m);
  $('#repo-count').textContent = `${fmtInt(list.length)} of ${fmtInt(m.repos.length)} repositories`;
  $$('#repo-table th[data-sort]').forEach((th) => {
    th.classList.toggle('sorted', th.dataset.sort === state.repo.sort);
    th.classList.toggle('desc', th.dataset.sort === state.repo.sort && state.repo.dir < 0);
  });
  $('#repo-band').value = state.repo.band;
  tbody.innerHTML = list.map((r) => {
    const sev = countBySeverity(r.findings);
    const checks = r.statusChecks ? (r.strictChecks ? 'y' : 'p') : 'n';
    const checksTip = r.statusChecks ? `${r.contexts.join(', ')}${r.strictChecks ? ' (strict)' : ' (not strict)'}` : 'No required status checks';
    const odd = r.defaultBranch && !STANDARD_BRANCHES.has(r.defaultBranch);
    return `<tr data-open-repo="${esc(r.full)}" class="${r.archived ? 'is-archived' : ''}">
      <td class="repo-cell"><b>${esc(r.name)}</b><small>${esc(r.org)}${r.archived ? ' · <span class="tag tag-muted">archived</span>' : ''}${r.visibility !== 'INTERNAL' ? ` · <span class="tag">${esc(r.visibility.toLowerCase())}</span>` : ''}</small>${r.description ? `<em>${esc(r.description)}</em>` : ''}</td>
      <td>${r.score == null ? '<span class="na">—</span>' : `<span class="score-pill" style="--c:${scoreColor(r.score)}">${fmtScore(r.score)}</span>`}</td>
      <td class="nowrap">${['high', 'medium', 'low'].map((s) => (sev[s] ? `<span class="mini-sev sev-${s}" data-tip="${SEV_LABEL[s]}: ${sev[s]}">${sev[s]}</span>` : '')).join('')}</td>
      <td>${r.isProtected ? `<span class="count-chip" data-tip="${r.protectedBy === 'legacy' ? 'Legacy branch protection' : `${r.rulesetCount} ruleset(s)`}">${r.protectedBy === 'legacy' ? 'legacy' : r.rulesetCount}</span>` : yes(false, 'Default branch not protected')}</td>
      <td><span class="yn ${checks}" data-tip="${esc(checksTip)}">${icon(checks === 'n' ? 'x' : 'check')}</span></td>
      <td><span class="count-chip ${r.approvals >= 2 ? 'good' : r.approvals === 1 ? 'mid' : 'bad'}">${r.approvals}</span></td>
      <td>${yes(r.signed, r.signed ? 'Signed commits required' : 'Signed commits not required')}</td>
      <td>${yes(r.codeowners, r.codeowners ? 'CODEOWNERS present' : r.codeOwnerReviews ? 'Code-owner review required, but no CODEOWNERS file' : 'No CODEOWNERS file')}</td>
      <td>${yes(r.dependabotAlerts, r.dependabotAlerts ? 'Dependabot alerts enabled' : 'Dependabot alerts disabled')}</td>
      <td>${yes(r.dependabotConfig, r.dependabotConfig ? 'dependabot.yml present' : 'No dependabot.yml')}</td>
      <td>${yes(!!r.description, r.description ? 'Has a description' : 'No description')}</td>
      <td><code class="${odd ? 'warn' : ''}" data-tip="${esc(odd ? `Non-standard default branch: ${r.defaultBranch}` : r.defaultBranch || '')}">${esc(r.defaultBranch || '—')}</code></td>
      <td class="nowrap muted">${esc(relDays(r.daysSincePush))}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="13" class="empty-state">No repositories match these filters.</td></tr>';
}

/* ─── View: Findings ──────────────────────────────────────────────────── */
function renderFindings(m) {
  const cats = [...new Set(m.findings.map((f) => f.category))].sort((a, b) => catLabel(a).localeCompare(catLabel(b)));
  return `
  <section class="page-head reveal"><div><div class="eyebrow">${icon('list')} Findings</div><h2>All ${fmtInt(m.findings.length)} GHQR findings</h2>
    <p>Grouped by rule, exactly as GHQR reported them.<span class="hint"> Expand a group for the recommendation and every affected organisation or repository.</span></p></div></section>
  <section class="card reveal">
    <div class="toolbar">
      <div class="sev-filters" id="sev-filters">${SEVERITIES.map((s) => `<button class="sev-toggle sev-${s}${state.finding.sev.has(s) ? ' on' : ''}" data-sev="${s}"><span class="dot" style="--c:var(--sev-${s})"></span>${SEV_LABEL[s]}<b>${fmtInt(m.sev[s])}</b></button>`).join('')}</div>
      <span class="grow"></span>
      <label class="search">${icon('search')}<input type="search" id="find-q" placeholder="Search findings or entities…" value="${esc(state.finding.q)}"></label>
      <select id="find-scope" aria-label="Scope"><option value="">All scopes</option><option value="enterprise">Enterprise</option><option value="org">Organisation</option><option value="repo">Repository</option></select>
      <select id="find-cat" aria-label="Category"><option value="">All categories</option>${cats.map((c) => `<option value="${esc(c)}">${esc(catLabel(c))}</option>`).join('')}</select>
      <button class="btn btn-primary" id="find-csv">${icon('download')} CSV</button>
    </div>
    <div class="find-summary" id="find-summary"></div>
    <div class="fgroups" id="fgroups"></div>
  </section>`;
}

function filteredGroups(m) {
  const f = state.finding;
  const q = f.q.trim().toLowerCase();
  const out = [];
  for (const g of m.groups) {
    if (!f.sev.has(g.severity) || (f.scope && g.scope !== f.scope) || (f.category && g.category !== f.category)) continue;
    const head = !q || [g.title, g.recommendation, g.ruleId, catLabel(g.category)].some((x) => String(x || '').toLowerCase().includes(q));
    const items = head ? g.items : g.items.filter((x) => x.entity.toLowerCase().includes(q) || x.issue.toLowerCase().includes(q));
    if (items.length) out.push({ g, items });
  }
  return out;
}

function renderFindingList(m) {
  const host = $('#fgroups');
  if (!host) return;
  $('#find-scope').value = state.finding.scope;
  $('#find-cat').value = state.finding.category;
  $$('#sev-filters .sev-toggle').forEach((b) => b.classList.toggle('on', state.finding.sev.has(b.dataset.sev)));
  const list = filteredGroups(m);
  const shown = list.flatMap((x) => x.items);
  const sev = countBySeverity(shown);
  $('#find-summary').innerHTML = `<span>Showing <b>${fmtInt(shown.length)}</b> findings in <b>${fmtInt(list.length)}</b> groups</span>${sevStack(sev)}`;
  const unit = (scope, n) => (scope === 'repo' ? plural(n, 'repository', 'repositories') : scope === 'org' ? plural(n, 'organisation') : plural(n, 'entity', 'entities'));
  const openAttr = (x) => (x.scope === 'repo' ? `data-open-repo="${esc(x.entity)}"` : x.scope === 'org' ? `data-open-org="${esc(x.entity)}"` : '');
  host.innerHTML = list.map(({ g, items }) => `
    <details class="fgroup sev-l-${g.severity}${g.positive ? ' positive' : ''}">
      <summary>
        ${sevPill(g.severity)}
        <span class="fg-title"><b>${esc(g.title)}</b><small>${esc(catLabel(g.category))} · ${esc(SCOPE_LABEL[g.scope])}${g.ruleId ? ` · <code>${esc(g.ruleId)}</code>` : ''}${g.positive ? ' · <span class="tag tag-good">no action required</span>' : ''}</small></span>
        <span class="fg-count"><b>${fmtInt(items.length)}</b><small>${esc(unit(g.scope, items.length).replace(/^[\d,]+ /, ''))}</small></span>
        ${icon('chevron', 'chev')}
      </summary>
      <div class="fg-body">
        <p class="fg-rec">${icon('bolt')}<span>${esc(g.recommendation)}</span></p>
        ${g.learnMore ? `<a class="link" href="${esc(g.learnMore)}" target="_blank" rel="noopener noreferrer">${icon('external')} Learn more</a>` : ''}
        ${g.varied
          ? `<div class="fg-rows">${items.map((x) => `<button class="fg-row" ${openAttr(x)}><span class="tag">${esc(SCOPE_LABEL[x.scope])}</span><b>${esc(x.entity)}</b><span>${esc(x.issue)}</span></button>`).join('')}</div>`
          : `<div class="fg-chips">${items.map((x) => `<button class="org-chip" ${openAttr(x)}>${esc(x.entity)}</button>`).join('')}</div>`}
      </div>
    </details>`).join('') || '<div class="empty-state">No findings match these filters.</div>';
}

/* ─── CSV export (formula-injection safe) ─────────────────────────────── */
function csvCell(v) {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function downloadCsv(name, header, rows) {
  const text = [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n');
  const blob = new Blob([`\ufeff${text}`], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
function exportRepos(m) {
  const list = filteredRepos(m);
  downloadCsv(`${m.enterprise?.slug || 'ghqr'}-repositories.csv`,
    ['Repository', 'Organisation', 'Archived', 'Visibility', 'Health score', 'High', 'Medium', 'Low', 'Rulesets', 'Required checks', 'Strict checks', 'Approvals', 'Signed commits', 'CODEOWNERS', 'Dependabot alerts', 'dependabot.yml', 'Description', 'Default branch', 'Language', 'Last push', 'Control gaps'],
    list.map((r) => {
      const s = countBySeverity(r.findings);
      return [r.full, r.org, r.archived, r.visibility, r.score == null ? '' : Math.round(r.score), s.high, s.medium, s.low, r.rulesetCount, r.contexts.join('; '), r.strictChecks, r.approvals, r.signed, r.codeowners, r.dependabotAlerts, r.dependabotConfig, r.description, r.defaultBranch, r.language || '', r.pushedAt ? r.pushedAt.toISOString() : '', r.failing.map((c) => c.title).join('; ')];
    }));
}
function exportFindings(m) {
  const rows = filteredGroups(m).flatMap(({ g, items }) => items.map((f) => [SEV_LABEL[f.severity], catLabel(f.category), SCOPE_LABEL[f.scope], f.entity, f.ruleId || '', f.issue, f.recommendation, f.learnMore || '']));
  downloadCsv(`${m.enterprise?.slug || 'ghqr'}-findings.csv`, ['Severity', 'Category', 'Scope', 'Entity', 'Rule', 'Finding', 'Recommendation', 'Learn more'], rows);
}

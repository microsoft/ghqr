/* ─── Charts: hand-built SVG/HTML, animated by CSS ─────────────────────── */
let chartSeq = 0;
const polar = (cx, cy, r, deg) => {
  const a = ((deg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
};
function arcPath(cx, cy, r, a0, a1) {
  const [x0, y0] = polar(cx, cy, r, a0);
  const [x1, y1] = polar(cx, cy, r, a1);
  const large = Math.abs(a1 - a0) > 180 ? 1 : 0;
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

/* 250° dial. Options: size, stroke, label, zones, needle, ticks, ghost (a faint second value), from (animate from value). */
function gauge(value, o = {}) {
  const size = o.size || 160;
  const stroke = o.stroke || Math.round(size * 0.08);
  const v = value == null ? null : clamp(value, 0, 100);
  const pad = o.zones ? Math.round(size * 0.06) : 3;
  const cx = size / 2, cy = size / 2;
  const r = size / 2 - stroke / 2 - pad;
  const A0 = -125, A1 = 125, SW = A1 - A0;
  const len = (2 * Math.PI * r * SW) / 360;
  const b = band(v);
  const id = `gg${++chartSeq}`;
  const track = arcPath(cx, cy, r, A0, A1);
  const off = (x) => (x == null ? len : len * (1 - clamp(x, 0, 100) / 100));
  const from = o.from == null ? len : off(o.from);
  const h = Math.round(size * 0.86);
  let s = `<svg class="gauge ${o.cls || ''}" viewBox="0 0 ${size} ${h}" width="${size}" height="${h}" role="img" aria-label="${esc(o.label || 'Score')}: ${fmtScore(v)} of 100">`;
  s += `<defs><linearGradient id="${id}-g" x1="0" y1="1" x2="1" y2="0"><stop offset="0" style="stop-color:var(--rag-${b.key}-2)"/><stop offset="1" style="stop-color:var(--rag-${b.key})"/></linearGradient>`;
  s += `<filter id="${id}-f" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="${(size / 40).toFixed(1)}" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
  if (o.zones) {
    const rz = r + stroke / 2 + pad * 0.55;
    for (const [a, z, k] of [[0, 60, 'red'], [60, 80, 'amber'], [80, 100, 'green']]) {
      s += `<path d="${arcPath(cx, cy, rz, A0 + (SW * a) / 100 + (a ? 0.8 : 0), A0 + (SW * z) / 100)}" class="g-zone" style="stroke:var(--rag-${k})" stroke-width="${Math.max(2, size * 0.012)}"/>`;
    }
  }
  s += `<path d="${track}" class="g-track" stroke-width="${stroke}"/>`;
  if (o.ticks) {
    for (let i = 0; i <= 20; i++) {
      const a = A0 + (SW * i) / 20;
      const major = i % 5 === 0;
      const [x0, y0] = polar(cx, cy, r - stroke / 2 - size * 0.02, a);
      const [x1, y1] = polar(cx, cy, r - stroke / 2 - size * (major ? 0.06 : 0.04), a);
      s += `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" class="g-tick${major ? ' major' : ''}"/>`;
    }
  }
  if (o.ghost != null) {
    s += `<path d="${track}" class="g-ghost" stroke-width="${stroke}" stroke-dasharray="${len.toFixed(2)} ${len.toFixed(2)}" stroke-dashoffset="${off(o.ghost).toFixed(2)}"/>`;
  }
  if (v != null) {
    s += `<path d="${track}" class="g-val" stroke-width="${stroke}" style="stroke:url(#${id}-g);--from:${from.toFixed(2)}" stroke-dasharray="${len.toFixed(2)} ${len.toFixed(2)}" stroke-dashoffset="${off(v).toFixed(2)}" filter="url(#${id}-f)"/>`;
  }
  if (o.needle && v != null) {
    const a = A0 + (SW * v) / 100;
    const a0 = o.from == null ? A0 : A0 + (SW * clamp(o.from, 0, 100)) / 100;
    const nl = r - stroke / 2 - size * 0.075;
    const w = size * 0.018;
    s += `<g class="g-needle" style="--a:${a.toFixed(1)}deg;--a0:${a0.toFixed(1)}deg;transform-origin:${cx}px ${cy}px">`;
    s += `<path d="M ${cx - w} ${cy} L ${cx} ${cy - nl} L ${cx + w} ${cy} Z" class="g-needle-body"/><circle cx="${cx}" cy="${cy}" r="${(size * 0.035).toFixed(1)}" class="g-hub"/></g>`;
  }
  const numY = o.needle ? cy + size * 0.27 : cy + size * 0.08;
  const numSize = o.needle ? size * 0.16 : size * 0.25;
  s += `<text x="${cx}" y="${numY.toFixed(1)}" class="g-num" style="font-size:${numSize.toFixed(1)}px" data-count="${v == null ? '' : Math.round(v)}" data-from="${o.from == null ? 0 : Math.round(o.from)}">${fmtScore(v)}</text>`;
  if (o.label) {
    const ly = o.needle ? numY + size * 0.075 : cy + size * 0.2;
    s += `<text x="${cx}" y="${ly.toFixed(1)}" class="g-label" style="font-size:${Math.max(10, size * 0.058).toFixed(1)}px">${esc(o.label)}</text>`;
  }
  return `${s}</svg>`;
}

/* Full-circle progress ring for a 0–1 ratio. */
function ring(ratio, o = {}) {
  const size = o.size || 96;
  const stroke = o.stroke || Math.round(size * 0.1);
  const r = (size - stroke) / 2 - 1;
  const c = 2 * Math.PI * r;
  const v = ratio == null ? null : clamp(ratio, 0, 1);
  const color = o.color || (v == null ? 'var(--rag-none)' : `var(--rag-${band(v * 100).key})`);
  let s = `<svg class="ring" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="${esc(o.label || '')} ${fmtPct(v)}">`;
  s += `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="ring-track" stroke-width="${stroke}"/>`;
  if (v != null) {
    s += `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="ring-val" stroke-width="${stroke}" style="stroke:${color};--c:${c.toFixed(2)}" stroke-dasharray="${(c * v).toFixed(2)} ${c.toFixed(2)}" transform="rotate(-90 ${size / 2} ${size / 2})"/>`;
  }
  s += `<text x="${size / 2}" y="${size / 2 + size * 0.07}" class="ring-num" style="font-size:${(size * 0.22).toFixed(1)}px">${o.text ?? fmtPct(v)}</text>`;
  return `${s}</svg>`;
}

/* Donut chart. segments: [{label, value, color, attrs}] */
function donut(segments, o = {}) {
  const size = o.size || 160;
  const stroke = o.stroke || Math.round(size * 0.13);
  const r = (size - stroke) / 2 - 2;
  const c = 2 * Math.PI * r;
  const total = sum(segments, (x) => x.value);
  let offset = 0;
  let s = `<svg class="donut" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="${esc(o.label || 'Distribution')}">`;
  s += `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="donut-track" stroke-width="${stroke}"/>`;
  s += `<g transform="rotate(-90 ${size / 2} ${size / 2})">`;
  segments.forEach((seg, i) => {
    if (!seg.value || !total) return;
    const len = (seg.value / total) * c;
    const gap = segments.filter((x) => x.value).length > 1 ? Math.min(2.5, len * 0.3) : 0;
    s += `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="donut-seg" stroke-width="${stroke}" style="stroke:${seg.color};--c:${c.toFixed(2)};--i:${i}" stroke-dasharray="${Math.max(0, len - gap).toFixed(2)} ${(c - len + gap).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" data-tip="${esc(`${seg.label}: ${fmtInt(seg.value)} (${fmtPct(seg.value / total)})`)}" ${seg.attrs || ''}/>`;
    offset += len;
  });
  s += '</g>';
  if (o.center != null) s += `<text x="${size / 2}" y="${size / 2 + size * 0.04}" class="donut-num" style="font-size:${(size * 0.2).toFixed(1)}px" ${o.countTo != null ? `data-count="${o.countTo}"` : ''}>${esc(o.center)}</text>`;
  if (o.sub) s += `<text x="${size / 2}" y="${size / 2 + size * 0.15}" class="donut-sub" style="font-size:${Math.max(10, size * 0.07).toFixed(1)}px">${esc(o.sub)}</text>`;
  return `${s}</svg>`;
}

/* Semicircular risk meter with four zones. level: 0 Low … 3 Critical */
function riskMeter(level, o = {}) {
  const size = o.size || 320;
  const cx = size / 2, cy = size * 0.56, r = size * 0.4, sw = size * 0.085;
  const zones = [['Low', 'var(--rag-green)'], ['Moderate', 'var(--sev-medium)'], ['High', 'var(--sev-high)'], ['Critical', 'var(--sev-critical)']];
  const seg = 180 / zones.length;
  const h = Math.round(size * 0.66);
  let s = `<svg class="risk" viewBox="0 0 ${size} ${h}" width="${size}" height="${h}" role="img" aria-label="Vulnerability risk: ${zones[level][0]}">`;
  zones.forEach(([label, color], i) => {
    const a0 = -90 + i * seg + 1.2, a1 = -90 + (i + 1) * seg - 1.2;
    s += `<path d="${arcPath(cx, cy, r, a0, a1)}" class="risk-zone${i === level ? ' on' : ''}" style="stroke:${color}" stroke-width="${sw}"/>`;
    const [lx, ly] = polar(cx, cy, r + sw * 1.3, (a0 + a1) / 2);
    s += `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" class="risk-label${i === level ? ' on' : ''}" style="font-size:${(size * 0.038).toFixed(1)}px">${label}</text>`;
  });
  const a = -90 + (level + 0.5) * seg;
  const nl = r - sw * 0.7, w = size * 0.016;
  s += `<g class="g-needle" style="--a:${a}deg;--a0:-90deg;transform-origin:${cx}px ${cy}px"><path d="M ${cx - w} ${cy} L ${cx} ${cy - nl} L ${cx + w} ${cy} Z" class="g-needle-body"/><circle cx="${cx}" cy="${cy}" r="${(size * 0.03).toFixed(1)}" class="g-hub"/></g>`;
  return `${s}</svg>`;
}

/* Horizontal bars. items: [{label, labelHtml, value, color, tip, attrs, valueHtml}] */
function hbars(items, o = {}) {
  const max = o.max ?? Math.max(1, ...items.map((i) => i.value || 0));
  return `<div class="hbars ${o.cls || ''}">${items.map((it, i) => `
    <div class="hbar${it.attrs ? ' clickable' : ''}" ${it.attrs || ''} ${it.tip ? `data-tip="${esc(it.tip)}"` : ''}>
      <div class="hbar-label" title="${esc(it.label)}">${it.labelHtml || esc(it.label)}</div>
      <div class="hbar-track"><div class="hbar-fill" style="--w:${((100 * (it.value || 0)) / max).toFixed(2)}%;--c:${it.color || 'var(--accent)'};--i:${i}"></div></div>
      <div class="hbar-val">${it.valueHtml ?? fmtInt(it.value)}</div>
    </div>`).join('')}</div>`;
}

/* Vertical columns. items: [{label, value, color, tip}] */
function vbars(items, o = {}) {
  const max = Math.max(1, ...items.map((i) => i.value || 0));
  return `<div class="vbars" style="--h:${o.height || 150}px">${items.map((it, i) => `
    <div class="vbar" data-tip="${esc(it.tip || `${it.label}: ${fmtInt(it.value)}`)}">
      <div class="vbar-val">${fmtInt(it.value)}</div>
      <div class="vbar-col"><div class="vbar-fill" style="--hh:${((100 * (it.value || 0)) / max).toFixed(2)}%;--c:${it.color || 'var(--accent)'};--i:${i}"></div></div>
      <div class="vbar-label">${esc(it.label)}</div>
    </div>`).join('')}</div>`;
}

/* One stacked bar split by severity. */
function sevStack(counts, o = {}) {
  const total = o.total ?? sum(SEVERITIES, (s) => counts[s] || 0);
  if (!total) return '<div class="stack empty"></div>';
  return `<div class="stack">${SEVERITIES.filter((s) => counts[s]).map((s, i) => `<span class="stack-seg" style="--w:${((100 * counts[s]) / total).toFixed(2)}%;--c:var(--sev-${s});--i:${i}" data-tip="${esc(`${SEV_LABEL[s]}: ${fmtInt(counts[s])}`)}"></span>`).join('')}</div>`;
}

/* Squarified treemap layout (Bruls et al.). items need a numeric `value`. */
function squarify(items, x, y, w, h) {
  const out = [];
  const total = sum(items, (i) => i.value);
  if (!total || w <= 0 || h <= 0) return out;
  const scale = (w * h) / total;
  const queue = items.map((item) => ({ item, area: item.value * scale }));
  let rect = { x, y, w, h };
  let row = [];
  const worst = (rw, side) => {
    const s = sum(rw, (r) => r.area);
    let mx = 0, mn = Infinity;
    for (const r of rw) { mx = Math.max(mx, r.area); mn = Math.min(mn, r.area); }
    return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
  };
  const layout = (rw) => {
    const s = sum(rw, (r) => r.area);
    if (rect.w >= rect.h) {
      const cw = s / rect.h;
      let yy = rect.y;
      for (const r of rw) { const hh = r.area / cw; out.push({ item: r.item, x: rect.x, y: yy, w: cw, h: hh }); yy += hh; }
      rect = { x: rect.x + cw, y: rect.y, w: rect.w - cw, h: rect.h };
    } else {
      const rh = s / rect.w;
      let xx = rect.x;
      for (const r of rw) { const ww = r.area / rh; out.push({ item: r.item, x: xx, y: rect.y, w: ww, h: rh }); xx += ww; }
      rect = { x: rect.x, y: rect.y + rh, w: rect.w, h: rect.h - rh };
    }
  };
  while (queue.length) {
    const side = Math.min(rect.w, rect.h);
    if (!row.length || worst([...row, queue[0]], side) <= worst(row, side)) row.push(queue.shift());
    else { layout(row); row = []; }
  }
  if (row.length) layout(row);
  return out;
}

/* Estate map: organisations sized by repository count, tiles coloured by repository score. */
function renderTreemap(m) {
  const host = $('#treemap');
  if (!host || !host.offsetParent) return;
  const W = host.clientWidth;
  const H = Math.round(clamp(W * 0.4, 340, 540));
  host.style.height = `${H}px`;
  const orgs = m.orgs.filter((o) => o.repos.length).map((o) => ({ o, value: o.repos.length })).sort((a, b) => b.value - a.value);
  const blocks = squarify(orgs, 0, 0, W, H);
  let html = '';
  for (const bl of blocks) {
    const o = bl.item.o;
    const head = bl.h > 44 && bl.w > 46 ? 24 : 0;
    html += `<div class="tm-org" style="left:${bl.x.toFixed(1)}px;top:${bl.y.toFixed(1)}px;width:${bl.w.toFixed(1)}px;height:${bl.h.toFixed(1)}px">`;
    if (head) html += `<button class="tm-head" data-open-org="${esc(o.login)}"><b>${esc(o.login)}</b><span>${fmtInt(o.repos.length)}</span>${o.score != null ? `<i style="--c:${scoreColor(o.score)}">${fmtScore(o.score)}</i>` : ''}</button>`;
    const repos = o.repos.slice().sort((a, b) => (b.score ?? -1) - (a.score ?? -1)).map((r) => ({ r, value: 1 }));
    const tiles = squarify(repos, 3, head + 3, bl.w - 6, bl.h - head - 6);
    for (const t of tiles) {
      const r = t.item.r;
      const gaps = r.failing.slice().sort((a, b) => b.weight - a.weight).slice(0, 3).map((c) => `• ${c.title}`).join('\n');
      const tip = `${r.full}\n${r.archived ? 'Archived (not scored)' : `Health ${fmtScore(r.score)} / 100 · ${r.failing.length} control gap${r.failing.length === 1 ? '' : 's'}`}${gaps && !r.archived ? `\n${gaps}` : ''}`;
      const label = t.w > 70 && t.h > 24 ? `<span>${esc(r.name)}</span>` : '';
      html += `<button class="tm-tile${r.archived ? ' archived' : ''}" style="left:${(t.x + 1).toFixed(1)}px;top:${(t.y + 1).toFixed(1)}px;width:${Math.max(1, t.w - 2).toFixed(1)}px;height:${Math.max(1, t.h - 2).toFixed(1)}px;--c:${scoreColor(r.score)}" data-open-repo="${esc(r.full)}" data-tip="${esc(tip)}" aria-label="${esc(r.full)}">${label}</button>`;
    }
    html += '</div>';
  }
  host.innerHTML = html;
}

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const sourceDir = path.join(__dirname, '..', 'src', 'js');
const source = fs.readdirSync(sourceDir).filter((name) => name.endsWith('.js')).sort()
  .map((name) => fs.readFileSync(path.join(sourceDir, name), 'utf8')).join('\n')
  .replace(/\nboot\(\);\s*$/, '\n');

function dashboard(report) {
  const elements = new Map();
  const classList = { contains: () => false, remove() {} };
  const document = {
    body: { classList },
    querySelector(selector) {
      if (!elements.has(selector)) {
        elements.set(selector, {
          classList,
          replaceChildren() { this.innerHTML = ''; this.textContent = ''; },
          removeAttribute() {},
        });
      }
      return elements.get(selector);
    },
    querySelectorAll: () => [],
  };
  const context = vm.createContext({
    URL,
    URLSearchParams,
    document,
    location: { hash: '', pathname: '', search: '' },
    report,
  });
  vm.runInContext(source, context);
  vm.runInContext("globalThis.model = analyse(report, 'example-report.json')", context);
  return context;
}

function reportFor(login) {
  return { organizations: { [login]: { security_alerts: { critical_dependabot: 1 } } } };
}

test('domain drawer renders report-supplied HTML as text', () => {
  const context = dashboard(reportFor('<img src="data:," onerror="globalThis.__ghqrSecurityProbe=1">'));
  const html = vm.runInContext("domainDrawer(model, model.domainMap.get('vuln'))", context);
  assert.ok(html.includes('<small>0% \u00b7 1 open in &lt;img src=&quot;data:,&quot; onerror=&quot;globalThis.__ghqrSecurityProbe=1&quot;&gt;</small>'));
  assert.doesNotMatch(html, /<img\b/i);
});

test('domain drawer preserves ordinary alert summaries', () => {
  const context = dashboard(reportFor('example-org'));
  const html = vm.runInContext("domainDrawer(model, model.domainMap.get('vuln'))", context);
  assert.ok(html.includes('<small>0% \u00b7 1 open in example-org</small>'));
});

test('unload releases the organization renderer reference to the raw report', () => {
  const report = reportFor('example-org');
  const context = dashboard(report);
  vm.runInContext('state.model = model; renderOrgs(model)', context);
  assert.strictEqual(vm.runInContext('orgCtx.raw', context), report);
  vm.runInContext('showLanding()', context);
  assert.strictEqual(vm.runInContext('state.model', context), null);
  assert.strictEqual(vm.runInContext('orgCtx', context), null);
});

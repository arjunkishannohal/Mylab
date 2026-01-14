// task/task31/capture.mjs
// Playwright Headless UI Capture for endpoint discovery
// Dynamic behavior:
// - If BASE_URL not set: infer from manual/har/*.har and prompt
// - If BASE_URL host not found in HAR: prompt user to confirm
// - If scope allowlist missing: infer exact hosts from HAR (else capture all)
// - Optionally auto-merge endpoints into a corpus file (MERGE_TO)

import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import readline from 'readline';

// Paths are relative to task/task31/
const HAR_DIR = process.env.HAR_DIR || '../../manual/har';
const OUTPUT_DIR = process.env.OUTPUT_DIR || '../../temp/agent1/ui_capture';
const SCOPE_FILE = process.env.SCOPE_FILE || '../../outputs/activesubdomain.txt';
const PAGES_FILE = process.env.PAGES_FILE || '';
const MERGE_TO = process.env.MERGE_TO || '';

const BASE_URL_ENV = process.env.BASE_URL || '';
const LOGIN_URL_ENV = process.env.LOGIN_URL || '';
const USERNAME = process.env.USERNAME || '';
const PASSWORD = process.env.PASSWORD || '';

const OVERALL_TIMEOUT_MS = Number.parseInt(process.env.OVERALL_TIMEOUT_MS || '0', 10) || 0;
const NAV_TIMEOUT_MS = Number.parseInt(process.env.NAV_TIMEOUT_MS || '20000', 10) || 20000;
const LOGIN_TIMEOUT_MS = Number.parseInt(process.env.LOGIN_TIMEOUT_MS || '30000', 10) || 30000;
const MAX_PAGES = Number.parseInt(process.env.MAX_PAGES || '0', 10) || 0; // 0 = no cap
const CLICK_LIMIT = Number.parseInt(process.env.CLICK_LIMIT || '20', 10) || 20;

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

function normalizeBaseUrl(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) return '';

  try {
    const u = new URL(trimmed);
    return `${u.protocol}//${u.host}`;
  } catch {
    try {
      const u = new URL(`https://${trimmed}`);
      return `${u.protocol}//${u.host}`;
    } catch {
      return '';
    }
  }
}

function listHarFiles(harDir) {
  try {
    const entries = fs.readdirSync(harDir, { withFileTypes: true });
    return entries
      .filter(e => e.isFile() && e.name.toLowerCase().endsWith('.har'))
      .map(e => path.join(harDir, e.name));
  } catch {
    return [];
  }
}

function collectHarHosts(harFiles) {
  const counts = new Map();

  for (const file of harFiles) {
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
      const entries = data?.log?.entries || [];

      for (const e of entries) {
        const url = e?.request?.url;
        if (!url) continue;

        try {
          const host = new URL(url).hostname.toLowerCase();
          counts.set(host, (counts.get(host) || 0) + 1);
        } catch {
          // ignore invalid URL
        }
      }
    } catch {
      // ignore unreadable har
    }
  }

  return counts;
}

function pickTopHost(hostCounts) {
  let bestHost = '';
  let bestCount = 0;

  for (const [host, count] of hostCounts.entries()) {
    if (count > bestCount) {
      bestHost = host;
      bestCount = count;
    }
  }

  return bestHost;
}

function loadScopeFromFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const hosts = raw
      .split('\n')
      .map(h => h.trim().toLowerCase())
      .filter(Boolean);
    return new Set(hosts);
  } catch {
    return null;
  }
}

function isInScope(url, scopeSet) {
  if (!scopeSet) return true;
  try {
    const host = new URL(url).hostname.toLowerCase();
    return scopeSet.has(host);
  } catch {
    return false;
  }
}

function loadPagesToVisit(filePath) {
  const defaults = [
    '/',
    '/dashboard',
    '/account',
    '/settings',
    '/profile',
    '/billing',
    '/orders',
    '/admin'
  ];

  if (!filePath) return defaults;

  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const extra = raw
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => {
        try {
          const u = new URL(line);
          return u.pathname + u.search;
        } catch {
          return line.startsWith('/') ? line : '/' + line;
        }
      });

    return [...new Set([...defaults, ...extra])];
  } catch {
    console.warn('[WARN] PAGES_FILE not found/readable; using defaults.');
    return defaults;
  }
}

function detectMergeTarget() {
  const candidates = [
    MERGE_TO,
    '../../outputs/url_corpus_all_in_scope.txt',
    '../../temp/agent1/url_corpus_all_in_scope.txt'
  ].filter(Boolean);

  for (const c of candidates) {
    try {
      const full = path.resolve(process.cwd(), c);

      if (fs.existsSync(full)) return full;

      const lower = full.toLowerCase();
      if (lower.includes(`${path.sep}outputs${path.sep}`)) return full;
    } catch {
      // ignore
    }
  }

  return '';
}

function mergeUniqueLines(targetFile, newLines) {
  let existing = new Set();

  if (fs.existsSync(targetFile)) {
    try {
      const raw = fs.readFileSync(targetFile, 'utf-8');
      existing = new Set(raw.split('\n').map(l => l.trim()).filter(Boolean));
    } catch {
      // keep empty
    }
  } else {
    fs.mkdirSync(path.dirname(targetFile), { recursive: true });
  }

  const toAppend = [];
  for (const line of newLines) {
    if (!existing.has(line)) {
      existing.add(line);
      toAppend.push(line);
    }
  }

  if (toAppend.length > 0) {
    fs.appendFileSync(targetFile, toAppend.join('\n') + '\n');
  }

  return toAppend.length;
}

(async () => {
  const startedAt = Date.now();
  const deadline = OVERALL_TIMEOUT_MS > 0 ? (startedAt + OVERALL_TIMEOUT_MS) : 0;
  const ensureTime = (label) => {
    if (deadline && Date.now() > deadline) {
      throw new Error(`Overall timeout reached during: ${label}`);
    }
  };

  const harFiles = listHarFiles(HAR_DIR);
  const harHostCounts = collectHarHosts(harFiles);
  const harTopHost = pickTopHost(harHostCounts);

  let baseUrl = normalizeBaseUrl(BASE_URL_ENV);

  if (!baseUrl) {
    if (harTopHost) {
      const answer = await ask(`No BASE_URL provided. Use most frequent HAR host '${harTopHost}'? (Y/n) `);
      if ((answer || '').trim().toLowerCase().startsWith('n')) {
        const manual = await ask('Enter BASE_URL (e.g., https://app.example.com): ');
        baseUrl = normalizeBaseUrl(manual);
      } else {
        baseUrl = `https://${harTopHost}`;
      }
    } else {
      const manual = await ask('No HAR hosts found. Enter BASE_URL (e.g., https://app.example.com): ');
      baseUrl = normalizeBaseUrl(manual);
    }
  }

  if (!baseUrl) {
    console.error('[!] BASE_URL is required. Aborting.');
    process.exit(2);
  }

  const baseHost = new URL(baseUrl).hostname.toLowerCase();
  if (harHostCounts.size > 0 && !harHostCounts.has(baseHost)) {
    const answer = await ask(`BASE_URL host '${baseHost}' not found in HAR traffic. Continue anyway? (y/N) `);
    if (!((answer || '').trim().toLowerCase().startsWith('y'))) {
      const manual = await ask('Enter correct BASE_URL: ');
      const corrected = normalizeBaseUrl(manual);
      if (!corrected) {
        console.error('[!] Invalid BASE_URL. Aborting.');
        process.exit(2);
      }
      baseUrl = corrected;
    }
  }

  const loginUrl = normalizeBaseUrl(LOGIN_URL_ENV) ? LOGIN_URL_ENV : `${baseUrl}/login`;

  let scopeSet = loadScopeFromFile(SCOPE_FILE);
  if (!scopeSet && harHostCounts.size > 0) {
    scopeSet = new Set([...harHostCounts.keys()]);
    console.warn(`[WARN] Scope file not found. Using HAR-derived exact hosts (${scopeSet.size}).`);
  }
  if (!scopeSet) {
    console.warn('[WARN] No scope allowlist found. Capturing all hosts (may include noise).');
  }

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outHar = path.join(OUTPUT_DIR, `capture_${timestamp}.har`);
  const outEndpoints = path.join(OUTPUT_DIR, 'endpoints_discovered.txt');
  const outReport = path.join(OUTPUT_DIR, 'capture_report.md');

  const pagesToVisit = loadPagesToVisit(PAGES_FILE);

  const pagesToVisitCapped = MAX_PAGES > 0 ? pagesToVisit.slice(0, MAX_PAGES) : pagesToVisit;

  const capturedUrls = new Set();
  const capturedRequests = [];
  const errors = [];
  const pagesVisited = [];

  console.log(`[*] Base URL: ${baseUrl}`);
  console.log(`[*] Login URL: ${loginUrl}`);
  console.log(`[*] HAR output: ${outHar}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    recordHar: { path: outHar, mode: 'full' },
    viewport: { width: 1280, height: 800 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PlaywrightCapture/1.0'
  });

  const page = await context.newPage();
  page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);
  page.setDefaultTimeout(NAV_TIMEOUT_MS);

  page.on('request', req => {
    const url = req.url();
    if (isInScope(url, scopeSet)) {
      capturedUrls.add(url.split('?')[0]);
      capturedRequests.push({ method: req.method(), url: url, type: req.resourceType() });
    }
  });

  page.on('pageerror', err => errors.push(`Page error: ${err.message}`));
  page.on('requestfailed', req => errors.push(`Request failed: ${req.url()}`));

  try {
    ensureTime('start');
    console.log('[*] Navigating to login...');
    await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: LOGIN_TIMEOUT_MS });
    pagesVisited.push(loginUrl);

    if (USERNAME && PASSWORD) {
      console.log('[*] Attempting login...');

      const emailSelectors = [
        'input[name="email"]',
        'input[name="username"]',
        'input[type="email"]',
        '#email',
        '#username'
      ];
      const passSelectors = ['input[name="password"]', 'input[type="password"]', '#password'];
      const submitSelectors = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Login")',
        'button:has-text("Sign in")'
      ];

      for (const sel of emailSelectors) {
        const el = await page.$(sel);
        if (el) {
          await el.fill(USERNAME);
          break;
        }
      }

      for (const sel of passSelectors) {
        const el = await page.$(sel);
        if (el) {
          await el.fill(PASSWORD);
          break;
        }
      }

      for (const sel of submitSelectors) {
        const el = await page.$(sel);
        if (el) {
          await el.click();
          break;
        }
      }

      await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
      console.log(`[*] Login attempt complete. Current URL: ${page.url()}`);
    } else {
      console.log('[*] No USERNAME/PASSWORD set; continuing without form login.');
    }

    for (const p of pagesToVisitCapped) {
      ensureTime('page-walk');
      const fullUrl = p.startsWith('http') ? p : `${baseUrl}${p}`;
      console.log(`[*] Visiting: ${fullUrl}`);
      try {
        await page.goto(fullUrl, { waitUntil: 'networkidle', timeout: 20000 });
        pagesVisited.push(fullUrl);
        await page.waitForTimeout(1000);
      } catch (e) {
        errors.push(`Navigation error (${fullUrl}): ${e.message}`);
      }
    }

    console.log('[*] Clicking interactive elements...');
    const clickables = await page.$$('button, [role="button"], a[href^="/"], [onclick]');
    for (const el of clickables.slice(0, CLICK_LIMIT)) {
      ensureTime('click-phase');
      try {
        await el.click({ timeout: 2000 });
        await page.waitForTimeout(300);
      } catch {
        // ignore
      }
    }
  } catch (e) {
    errors.push(`Fatal flow error: ${e.message}`);
  }

  await context.close();
  await browser.close();

  const sortedUrls = [...capturedUrls].sort();
  fs.writeFileSync(outEndpoints, sortedUrls.join('\n') + '\n');

  const mergeTarget = detectMergeTarget();
  let mergedCount = 0;
  if (mergeTarget) {
    mergedCount = mergeUniqueLines(mergeTarget, sortedUrls);
    console.log(`[+] Merged ${mergedCount} new endpoints into: ${mergeTarget}`);
  } else {
    console.log('[*] No merge target detected. Set MERGE_TO to auto-merge into your corpus.');
  }

  const apiLike = capturedRequests.filter(r => r.url.includes('/api/') || r.type === 'fetch' || r.type === 'xhr');
  const postReqs = capturedRequests.filter(r => r.method === 'POST');

  const report = `# Playwright UI Capture Report\n\n## Summary\n- Date: ${new Date().toISOString()}\n- Base URL: ${baseUrl}\n- Login URL: ${loginUrl}\n- HAR saved: ${outHar}\n- Total requests captured: ${capturedRequests.length}\n- Unique endpoints: ${sortedUrls.length}\n- API/XHR requests: ${apiLike.length}\n- POST requests: ${postReqs.length}\n- Pages visited: ${pagesVisited.length}\n- HAR files available for inference: ${harFiles.length}\n- Auto-merged new endpoints: ${mergedCount}\n\n## Errors (${errors.length})\n${errors.length ? errors.map(e => '- ' + e).join('\n') : 'None'}\n\n## Pages visited\n${pagesVisited.map(p => '- ' + p).join('\n')}\n\n## API/XHR endpoints (first 30)\n${apiLike.slice(0, 30).map(r => '- [' + r.method + '] ' + r.url).join('\n')}\n\n## POST endpoints (first 20)\n${postReqs.slice(0, 20).map(r => '- ' + r.url).join('\n')}\n`;

  fs.writeFileSync(outReport, report);

  console.log(`\n[+] Done`);
  console.log(`[+] Endpoints: ${outEndpoints} (${sortedUrls.length} unique)`);
  console.log(`[+] Report: ${outReport}`);
})();

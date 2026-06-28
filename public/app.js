const form = document.getElementById('scan-form');
const emailForm = document.getElementById('email-form');
const urlInput = document.getElementById('url-input');
const emailInput = document.getElementById('email-input');
const scanBtn = document.getElementById('scan-btn');
const emailBtn = document.getElementById('email-btn');
const formError = document.getElementById('form-error');
const emailError = document.getElementById('email-error');
const resultsSection = document.getElementById('results');
const historyPanel = document.getElementById('history-panel');
const historyList = document.getElementById('history-list');
const historyEmpty = document.getElementById('history-empty');
const themeToggle = document.getElementById('theme-toggle');
const historyToggle = document.getElementById('history-toggle');
const clearHistoryBtn = document.getElementById('clear-history');
const expandUrlsCheck = document.getElementById('expand-urls');

const statTotal = document.getElementById('stat-total');
const statThreats = document.getElementById('stat-threats');
const statSafe = document.getElementById('stat-safe');

const RING_CIRCUMFERENCE = 327;
const HISTORY_KEY = 'phishguard_history';
const STATS_KEY = 'phishguard_stats';
const THEME_KEY = 'phishguard_theme';

const SUMMARIES = {
  safe: 'This URL shows few or no phishing indicators. Still verify the source before sharing credentials.',
  caution: 'Some minor red flags were found. Proceed with caution and double-check the sender.',
  suspicious: 'Multiple suspicious patterns detected. Avoid entering personal or financial information.',
  phishing: 'Strong phishing indicators found. Do not visit this link or enter any credentials.',
};

const CATEGORY_LABELS = {
  impersonation: 'Brand Impersonation',
  domain: 'Domain Analysis',
  transport: 'SSL / Transport',
  obfuscation: 'Obfuscation',
  content: 'Content Signals',
  general: 'General',
};

let lastResult = null;

initTheme();
loadStats();
loadHistory();

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

document.querySelectorAll('.example-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    switchTab('url');
    urlInput.value = chip.dataset.url;
    form.requestSubmit();
  });
});

themeToggle.addEventListener('click', toggleTheme);
historyToggle.addEventListener('click', () => historyPanel.classList.toggle('hidden'));
clearHistoryBtn.addEventListener('click', clearHistory);

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideError(formError);
  setLoading(scanBtn, true);

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: urlInput.value.trim(),
        expandShortUrls: expandUrlsCheck.checked,
      }),
    });
    const data = await res.json();
    if (!res.ok) { showError(formError, data.error); return; }

    lastResult = data;
    renderUrlResults(data);
    saveHistory({ type: 'url', input: data.input, verdict: data.verdict, score: data.riskScore, at: data.analyzedAt });
    updateStats(data.verdict);
  } catch {
    showError(formError, 'Network error. Make sure the server is running.');
  } finally {
    setLoading(scanBtn, false);
  }
});

emailForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideError(emailError);
  setLoading(emailBtn, true);

  try {
    const res = await fetch('/api/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: emailInput.value.trim() }),
    });
    const data = await res.json();
    if (!res.ok) { showError(emailError, data.error); return; }

    lastResult = data;
    renderEmailResults(data);
    saveHistory({ type: 'email', input: `${data.emailMeta.urlCount} URLs`, verdict: data.overallVerdict, score: data.overallScore, at: data.analyzedAt });
    updateStats(data.overallVerdict);
  } catch {
    showError(emailError, 'Network error. Make sure the server is running.');
  } finally {
    setLoading(emailBtn, false);
  }
});

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle('active', active);
    t.setAttribute('aria-selected', active);
  });
  document.getElementById('tab-url').classList.toggle('hidden', name !== 'url');
  document.getElementById('tab-email').classList.toggle('hidden', name !== 'email');
}

function setLoading(btn, loading) {
  btn.disabled = loading;
  btn.querySelector('.btn-text').classList.toggle('hidden', loading);
  btn.querySelector('.btn-loader').classList.toggle('hidden', !loading);
}

function showError(el, msg) { el.textContent = msg; el.classList.remove('hidden'); }
function hideError(el) { el.classList.add('hidden'); }

function renderUrlResults(data) {
  resultsSection.classList.remove('hidden');
  resultsSection.innerHTML = `
    ${verdictCard(data)}
    <div class="action-bar">
      <button type="button" class="btn-secondary" onclick="copyReport()">Copy Report</button>
      <button type="button" class="btn-secondary" onclick="exportJson()">Export JSON</button>
    </div>
    ${data.expansion?.expanded ? expansionCard(data.expansion) : ''}
    <div class="details-grid">
      <div class="card detail-card"><h3>URL Details</h3>${urlDetailsHtml(data)}</div>
      <div class="card detail-card"><h3>DNS & SSL</h3>${dnsSslHtml(data)}</div>
    </div>
    ${categoriesHtml(data.categories)}
    ${recommendationsHtml(data.recommendations, data.verdictColor)}
    ${checksHtml(data.checks)}
  `;
  animateRing(data.riskScore, data.verdictColor);
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderEmailResults(data) {
  const color = verdictColor(data.overallVerdict);
  const label = verdictLabel(data.overallVerdict);

  resultsSection.classList.remove('hidden');
  resultsSection.innerHTML = `
    <div class="verdict-card card">
      <div class="verdict-ring">
        <svg viewBox="0 0 120 120" class="score-ring">
          <circle cx="60" cy="60" r="52" class="ring-bg"/>
          <circle cx="60" cy="60" r="52" class="ring-fill" id="ring-fill"/>
        </svg>
        <div class="verdict-center">
          <span class="risk-score" id="risk-score">${data.overallScore}</span>
          <span class="risk-label">Risk</span>
        </div>
      </div>
      <div class="verdict-info">
        <h2 style="color:${color}">${label}</h2>
        <p class="verdict-domain">${data.emailMeta.urlCount} URL(s) found in email</p>
        <p class="verdict-summary">${SUMMARIES[data.overallVerdict] || SUMMARIES.caution}</p>
      </div>
    </div>
    ${data.emailMeta.hasSuspiciousLanguage ? `
      <div class="card alert-card">
        <h3>Suspicious Language Detected</h3>
        <p>Phrases found: ${data.emailMeta.phraseHits.map(escapeHtml).join(', ')}</p>
      </div>` : ''}
    <div class="card">
      <h3 class="section-title">Extracted URLs</h3>
      <div class="email-urls">
        ${data.urlResults.map((r) => emailUrlRow(r)).join('')}
      </div>
    </div>
  `;
  animateRing(data.overallScore, color);
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function verdictCard(data) {
  return `
    <div class="verdict-card card">
      <div class="verdict-ring">
        <svg viewBox="0 0 120 120" class="score-ring">
          <circle cx="60" cy="60" r="52" class="ring-bg"/>
          <circle cx="60" cy="60" r="52" class="ring-fill" id="ring-fill"/>
        </svg>
        <div class="verdict-center">
          <span class="risk-score" id="risk-score">${data.riskScore}</span>
          <span class="risk-label">Risk</span>
        </div>
      </div>
      <div class="verdict-info">
        <h2 id="verdict-label" style="color:${data.verdictColor}">${escapeHtml(data.verdictLabel)}</h2>
        <p class="verdict-domain">${escapeHtml(data.analyzedUrl || data.normalizedUrl)}</p>
        <p class="verdict-summary">${SUMMARIES[data.verdict]}</p>
      </div>
    </div>`;
}

function expansionCard(exp) {
  return `
    <div class="card expansion-card">
      <h3>URL Expansion</h3>
      <p class="expansion-note">Shortened URL expanded through ${exp.hops} redirect(s)</p>
      <div class="redirect-chain">
        ${exp.chain.map((hop, i) => `
          <div class="chain-step">
            <span class="chain-num">${i + 1}</span>
            <span class="chain-url">${escapeHtml(hop.url)}</span>
            ${hop.status ? `<span class="chain-status">${hop.status}</span>` : ''}
          </div>`).join('')}
      </div>
    </div>`;
}

function urlDetailsHtml(data) {
  return `<dl class="detail-list">
    <div><dt>Original Input</dt><dd>${escapeHtml(data.input)}</dd></div>
    <div><dt>Domain</dt><dd>${escapeHtml(data.domain)}</dd></div>
    <div><dt>Protocol</dt><dd>${escapeHtml(data.protocol.toUpperCase())}</dd></div>
    <div><dt>Path</dt><dd>${escapeHtml(data.path || '/')}</dd></div>
    ${data.query ? `<div><dt>Query</dt><dd>${escapeHtml(data.query)}</dd></div>` : ''}
    <div><dt>Scanned At</dt><dd>${new Date(data.analyzedAt).toLocaleString()}</dd></div>
  </dl>`;
}

function dnsSslHtml(data) {
  let html = '';
  if (data.dns?.resolved) {
    html += `<div class="dns-ok">✓ Domain resolves</div>
      <div class="dns-addresses">${data.dns.addresses.map(escapeHtml).join('<br>')}</div>`;
    if (data.dns.isPrivate) html += `<div class="dns-fail" style="margin-top:0.5rem">⚠ Private IP detected</div>`;
  } else {
    html += `<div class="dns-fail">✗ Could not resolve domain</div>`;
  }

  if (data.ssl) {
    html += '<hr class="divider">';
    if (data.ssl.error) {
      html += `<div class="dns-fail">SSL: ${escapeHtml(data.ssl.error)}</div>`;
    } else {
      const ok = data.ssl.valid;
      html += `<div class="${ok ? 'dns-ok' : 'dns-fail'}">${ok ? '✓' : '✗'} SSL Certificate</div>
        <dl class="detail-list" style="margin-top:0.5rem">
          <div><dt>Issuer</dt><dd>${escapeHtml(data.ssl.issuer)}</dd></div>
          <div><dt>Subject</dt><dd>${escapeHtml(data.ssl.subject)}</dd></div>
          <div><dt>Expires</dt><dd>${new Date(data.ssl.validTo).toLocaleDateString()} (${data.ssl.daysRemaining}d)</dd></div>
        </dl>`;
    }
  }
  return html;
}

function categoriesHtml(categories) {
  if (!categories?.length) return '';
  const max = Math.max(...categories.map((c) => c.score), 1);
  return `
    <div class="card">
      <h3 class="section-title">Risk Breakdown</h3>
      <div class="category-bars">
        ${categories.map((c) => `
          <div class="category-row">
            <span class="category-name">${CATEGORY_LABELS[c.name] || c.name}</span>
            <div class="category-track"><div class="category-fill" style="width:${(c.score / max) * 100}%"></div></div>
            <span class="category-score">${c.score}</span>
          </div>`).join('')}
      </div>
    </div>`;
}

function recommendationsHtml(recs, color) {
  if (!recs?.length) return '';
  return `
    <div class="card recommendations-card" style="border-left: 3px solid ${color}">
      <h3 class="section-title">Recommendations</h3>
      <ul class="rec-list">${recs.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
    </div>`;
}

function checksHtml(checks) {
  if (!checks?.length) {
    return `<div class="card checks-card"><h3 class="section-title">Security Checks</h3>
      <p class="no-checks">No suspicious indicators detected.</p></div>`;
  }
  return `
    <div class="card checks-card">
      <h3 class="section-title">Security Checks <span class="badge">${checks.length} issue${checks.length > 1 ? 's' : ''}</span></h3>
      <ul class="checks-list">
        ${checks.map((c) => `
          <li class="check-item check-item--${c.severity}">
            <span class="check-severity">${c.severity}</span>
            <div class="check-body">
              <strong>${escapeHtml(c.message)}</strong>
              <p>${escapeHtml(c.detail)}</p>
              <span class="check-category">${CATEGORY_LABELS[c.category] || c.category}</span>
            </div>
            <span class="check-score">+${c.score}</span>
          </li>`).join('')}
      </ul>
    </div>`;
}

function emailUrlRow(r) {
  if (r.error) {
    return `<div class="email-url-row email-url-row--error">
      <span>${escapeHtml(r.input)}</span><span class="verdict-pill">Error</span></div>`;
  }
  const color = verdictColor(r.verdict);
  return `<div class="email-url-row" onclick="rescanUrl('${escapeJs(r.input)}')">
    <div class="email-url-info">
      <span class="email-url-text">${escapeHtml(r.input)}</span>
      <span class="email-url-domain">${escapeHtml(r.domain || '')}</span>
    </div>
    <span class="verdict-pill" style="background:${color}22;color:${color}">${escapeHtml(r.verdictLabel || r.verdict)}</span>
    <span class="email-url-score">${r.riskScore}</span>
  </div>`;
}

function animateRing(score, color) {
  const ring = document.getElementById('ring-fill');
  const scoreEl = document.getElementById('risk-score');
  if (!ring || !scoreEl) return;
  scoreEl.textContent = score;
  scoreEl.style.color = color;
  ring.style.stroke = color;
  ring.style.strokeDashoffset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;
}

function verdictColor(v) {
  return { safe: '#22c55e', caution: '#eab308', suspicious: '#f97316', phishing: '#ef4444' }[v] || '#94a3b8';
}

function verdictLabel(v) {
  return { safe: 'Likely Safe', caution: 'Use Caution', suspicious: 'Suspicious', phishing: 'Likely Phishing' }[v] || v;
}

window.copyReport = function () {
  if (!lastResult) return;
  const text = lastResult.urlResults
    ? formatEmailReport(lastResult)
    : formatUrlReport(lastResult);
  navigator.clipboard.writeText(text).then(() => toast('Report copied'));
};

window.exportJson = function () {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `phishguard-report-${Date.now()}.json`;
  a.click();
  toast('JSON exported');
};

window.rescanUrl = function (url) {
  switchTab('url');
  urlInput.value = url;
  form.requestSubmit();
};

function formatUrlReport(d) {
  return `PhishGuard Report\nURL: ${d.input}\nVerdict: ${d.verdictLabel} (Score: ${d.riskScore})\n\nChecks:\n${d.checks.map((c) => `- [${c.severity}] ${c.message}: ${c.detail}`).join('\n')}\n\nRecommendations:\n${d.recommendations.map((r) => `- ${r}`).join('\n')}`;
}

function formatEmailReport(d) {
  return `PhishGuard Email Report\nURLs: ${d.emailMeta.urlCount}\nOverall: ${d.overallVerdict} (Score: ${d.overallScore})\n\n${d.urlResults.map((r) => `${r.input} → ${r.verdictLabel || r.error} (${r.riskScore || 0})`).join('\n')}`;
}

function saveHistory(entry) {
  const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  history.unshift(entry);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20)));
  loadHistory();
}

function loadHistory() {
  const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  historyEmpty.classList.toggle('hidden', history.length > 0);
  historyList.innerHTML = history.map((h) => `
    <li class="history-item" data-input="${escapeAttr(h.input)}" data-type="${h.type}">
      <span class="history-verdict" style="color:${verdictColor(h.verdict)}">${h.verdict}</span>
      <span class="history-input">${escapeHtml(h.input.slice(0, 40))}${h.input.length > 40 ? '…' : ''}</span>
      <span class="history-score">${h.score}</span>
    </li>`).join('');

  historyList.querySelectorAll('.history-item').forEach((item, i) => {
    item.addEventListener('click', () => {
      if (history[i].type === 'url') {
        switchTab('url');
        urlInput.value = history[i].input;
        form.requestSubmit();
      }
    });
  });
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  loadHistory();
}

function updateStats(verdict) {
  const stats = JSON.parse(localStorage.getItem(STATS_KEY) || '{"total":0,"threats":0,"safe":0}');
  stats.total++;
  if (verdict === 'phishing' || verdict === 'suspicious') stats.threats++;
  if (verdict === 'safe') stats.safe++;
  localStorage.setItem(STATS_KEY, JSON.stringify(stats));
  loadStats();
}

function loadStats() {
  const stats = JSON.parse(localStorage.getItem(STATS_KEY) || '{"total":0,"threats":0,"safe":0}');
  statTotal.textContent = stats.total;
  statThreats.textContent = stats.threats;
  statSafe.textContent = stats.safe;
}

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light') document.body.classList.add('light');
  updateThemeIcon();
}

function toggleTheme() {
  document.body.classList.toggle('light');
  localStorage.setItem(THEME_KEY, document.body.classList.contains('light') ? 'light' : 'dark');
  updateThemeIcon();
}

function updateThemeIcon() {
  const isLight = document.body.classList.contains('light');
  document.querySelector('.icon-sun').classList.toggle('hidden', isLight);
  document.querySelector('.icon-moon').classList.toggle('hidden', !isLight);
}

function toast(msg) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

function escapeAttr(str) { return String(str ?? '').replace(/"/g, '&quot;'); }
function escapeJs(str) { return String(str ?? '').replace(/'/g, "\\'"); }

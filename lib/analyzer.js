const dns = require('dns').promises;
const { URL } = require('url');
const { isShortener, expandUrl } = require('./urlExpander');
const { checkSsl } = require('./sslChecker');

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'password', 'credential', 'wallet', 'suspend', 'unlock',
  'validation', 'authenticate', 'billing', 'payment', 'refund', 'invoice',
];

const SUSPICIOUS_TLDS = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
  'buzz', 'rest', 'fit', 'cam', 'monster', 'sbs', 'cfd',
];

const TRUSTED_BRANDS = [
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'meta',
  'instagram', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'linkedin', 'twitter', 'dropbox', 'icloud', 'outlook', 'office365',
  'ebay', 'stripe', 'coinbase', 'binance', 'whatsapp', 'telegram',
];

const TRUSTED_DOMAINS = new Set([
  'google.com', 'www.google.com', 'accounts.google.com',
  'amazon.com', 'www.amazon.com',
  'paypal.com', 'www.paypal.com',
  'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
  'apple.com', 'www.apple.com', 'icloud.com',
  'facebook.com', 'www.facebook.com', 'meta.com',
  'github.com', 'www.github.com',
  'linkedin.com', 'www.linkedin.com',
  'netflix.com', 'www.netflix.com',
  'youtube.com', 'www.youtube.com',
  'twitter.com', 'www.twitter.com', 'x.com',
]);

const LEGITIMATE_BRAND_SUFFIXES = {
  paypal: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazonaws.com'],
  google: ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com'],
  apple: ['apple.com', 'icloud.com'],
  facebook: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com'],
  meta: ['meta.com', 'facebook.com', 'instagram.com'],
  instagram: ['instagram.com'],
  netflix: ['netflix.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  citibank: ['citibank.com'],
  linkedin: ['linkedin.com'],
  twitter: ['twitter.com', 'x.com'],
  dropbox: ['dropbox.com'],
  icloud: ['icloud.com'],
  outlook: ['outlook.com', 'live.com'],
  office365: ['office.com', 'microsoft.com'],
  ebay: ['ebay.com'],
  stripe: ['stripe.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
  whatsapp: ['whatsapp.com'],
  telegram: ['telegram.org'],
};

const RECOMMENDATIONS = {
  phishing: [
    'Do not click this link or enter any credentials.',
    'Report the message to your IT/security team or email provider.',
    'Delete the email and block the sender if applicable.',
    'If you already clicked, change passwords and enable 2FA immediately.',
  ],
  suspicious: [
    'Avoid entering personal or financial information on this site.',
    'Verify the link through the official app or by typing the URL manually.',
    'Contact the organization directly using a known phone number.',
  ],
  caution: [
    'Double-check the sender and context before proceeding.',
    'Look for spelling errors and mismatched sender addresses.',
    'When in doubt, navigate to the site directly instead of clicking.',
  ],
  safe: [
    'No major red flags detected, but always verify unexpected links.',
    'Ensure the page shows a valid HTTPS padlock before entering data.',
  ],
};

function isLegitimateBrandHost(brand, hostname) {
  const suffixes = LEGITIMATE_BRAND_SUFFIXES[brand];
  if (!suffixes) {
    return hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
  }
  return suffixes.some(
    (suffix) => hostname === suffix || hostname.endsWith('.' + suffix)
  );
}

function normalizeInput(raw) {
  let input = raw.trim();
  if (!input) throw new Error('Please enter a URL to analyze.');
  if (!/^https?:\/\//i.test(input)) {
    input = 'https://' + input;
  }
  return input;
}

function getHostnameParts(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const tld = parts.length >= 2 ? parts.slice(-1)[0] : '';
  const sld = parts.length >= 2 ? parts.slice(-2, -1)[0] : hostname;
  const subdomains = parts.length > 2 ? parts.slice(0, -2) : [];
  const registeredDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  return { parts, tld, sld, subdomains, registeredDomain };
}

function isIpAddress(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
    /^\[[0-9a-f:]+\]$/i.test(hostname);
}

function isPrivateIp(ip) {
  const clean = ip.replace(/^\[|\]$/g, '');
  if (/^10\./.test(clean)) return true;
  if (/^192\.168\./.test(clean)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(clean)) return true;
  if (/^127\./.test(clean)) return true;
  if (clean === '0.0.0.0') return true;
  return false;
}

function countChar(str, char) {
  return (str.match(new RegExp('\\' + char, 'g')) || []).length;
}

function hasHomographChars(str) {
  return /[^\x00-\x7F]/.test(str) ||
    /[а-яА-Я]/.test(str) ||
    /[α-ωΑ-Ω]/.test(str);
}

function decodePunycode(hostname) {
  if (!hostname.includes('xn--')) return null;
  try {
    return hostname.split('.').map((part) => {
      if (part.startsWith('xn--')) {
        return part.codePointAt ? part : part;
      }
      return part;
    }).join('.');
  } catch {
    return null;
  }
}

function extractBrandMentions(hostname, pathname) {
  const haystack = `${hostname} ${pathname}`.toLowerCase();
  const mentions = [];

  for (const brand of TRUSTED_BRANDS) {
    if (!haystack.includes(brand)) continue;
    if (!isLegitimateBrandHost(brand, hostname.toLowerCase())) {
      mentions.push(brand);
    }
  }
  return [...new Set(mentions)];
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i - 1] === a[j - 1]
        ? matrix[i - 1][j - 1]
        : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

function findTyposquat(hostname) {
  const { sld, registeredDomain } = getHostnameParts(hostname);
  const matches = [];

  for (const brand of TRUSTED_BRANDS) {
    if (registeredDomain.includes(brand)) continue;
    const distance = levenshtein(sld, brand);
    if (distance > 0 && distance <= 2 && sld.length >= 4) {
      matches.push({ brand, distance, domain: registeredDomain });
    }
  }
  return matches;
}

function scoreCheck(score, severity, message, detail, category = 'general') {
  return { score, severity, message, detail, category };
}

function buildCategories(checks) {
  const cats = {};
  for (const c of checks) {
    cats[c.category] = (cats[c.category] || 0) + c.score;
  }
  return Object.entries(cats)
    .map(([name, score]) => ({ name, score }))
    .sort((a, b) => b.score - a.score);
}

async function analyzeUrl(rawInput, options = {}) {
  const { expandShortUrls = true } = options;
  const normalized = normalizeInput(rawInput);
  let parsed;

  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error('Invalid URL format. Example: https://example.com/login');
  }

  let expandResult = null;
  let analyzeTarget = normalized;

  if (expandShortUrls && isShortener(parsed.hostname)) {
    expandResult = await expandUrl(normalized);
    analyzeTarget = expandResult.final;
    try {
      parsed = new URL(analyzeTarget);
    } catch {
      throw new Error('Shortened URL could not be resolved to a valid destination.');
    }
  }

  const hostname = parsed.hostname.replace(/^www\./, '');
  const fullUrl = parsed.href;
  const checks = [];
  let riskScore = 0;

  const add = (score, severity, message, detail, category = 'general') => {
    checks.push(scoreCheck(score, severity, message, detail, category));
    riskScore += score;
  };

  if (expandResult?.expanded) {
    add(8, 'medium', 'URL shortener detected', `Expanded through ${expandResult.hops} redirect(s) to reveal destination.`, 'obfuscation');
    if (expandResult.hops >= 3) {
      add(10, 'high', 'Multiple redirect hops', `${expandResult.hops} redirects used — common tactic to hide malicious destinations.`, 'obfuscation');
    }
  }

  if (TRUSTED_DOMAINS.has(hostname) || TRUSTED_DOMAINS.has(parsed.hostname)) {
    return buildResult(rawInput, normalized, parsed, checks, 0, 'safe', { resolved: true, addresses: [] }, null, expandResult);
  }

  if (parsed.protocol !== 'https:') {
    add(15, 'high', 'Not using HTTPS', 'Legitimate sites usually use secure HTTPS connections.', 'transport');
  }

  if (isIpAddress(parsed.hostname)) {
    add(35, 'critical', 'Uses IP address instead of domain', 'Phishing links often use raw IP addresses to hide identity.', 'domain');
  }

  if (fullUrl.includes('@')) {
    add(30, 'critical', 'Contains @ symbol in URL', 'The @ trick can hide the real destination domain.', 'obfuscation');
  }

  if (fullUrl.includes('%')) {
    add(10, 'medium', 'URL-encoded characters detected', 'Encoding may be used to obfuscate malicious destinations.', 'obfuscation');
  }

  if (/\/\/[^/]/.test(fullUrl.replace(/^https?:\/\//, ''))) {
    add(15, 'high', 'Double-slash redirect trick', 'Malformed slashes can bypass filters and hide the real host.', 'obfuscation');
  }

  const urlLength = fullUrl.length;
  if (urlLength > 75) {
    add(10, 'medium', 'Unusually long URL', `URL length is ${urlLength} characters.`, 'obfuscation');
  }
  if (urlLength > 150) {
    add(15, 'high', 'Extremely long URL', 'Very long URLs are a common phishing tactic.', 'obfuscation');
  }

  const hyphenCount = countChar(hostname, '-');
  if (hyphenCount >= 3) {
    add(12, 'medium', 'Many hyphens in domain', `${hyphenCount} hyphens detected — often used in fake domains.`, 'domain');
  }

  const { tld, subdomains, registeredDomain, sld } = getHostnameParts(parsed.hostname);

  if (SUSPICIOUS_TLDS.includes(tld)) {
    add(18, 'high', 'Suspicious top-level domain', `.${tld} TLDs are frequently abused in phishing campaigns.`, 'domain');
  }

  if (subdomains.length >= 3) {
    add(15, 'high', 'Excessive subdomains', `${subdomains.length} subdomains may indicate domain spoofing.`, 'domain');
  }

  const keywordHits = SUSPICIOUS_KEYWORDS.filter((kw) =>
    fullUrl.toLowerCase().includes(kw)
  );
  if (keywordHits.length >= 2) {
    add(12, 'medium', 'Multiple urgency/login keywords', `Found: ${keywordHits.slice(0, 5).join(', ')}`, 'content');
  } else if (keywordHits.length === 1) {
    add(5, 'low', 'Suspicious keyword in URL', `Contains "${keywordHits[0]}" — common in phishing pages.`, 'content');
  }

  if (parsed.hostname.includes('xn--')) {
    add(25, 'critical', 'Punycode domain detected', 'Internationalized domain names (xn--) can mimic trusted brands using look-alike characters.', 'domain');
  }

  if (hasHomographChars(parsed.hostname)) {
    add(40, 'critical', 'Homograph / unicode characters in domain', 'Attackers use look-alike characters to mimic trusted brands.', 'domain');
  }

  const brandMentions = extractBrandMentions(parsed.hostname, parsed.pathname);
  if (brandMentions.length > 0) {
    add(35, 'critical', 'Possible brand impersonation', `References "${brandMentions.join('", "')}" but domain is ${registeredDomain}.`, 'impersonation');
  }

  const typos = findTyposquat(parsed.hostname);
  if (typos.length > 0) {
    const top = typos[0];
    add(28, 'high', 'Possible typosquatting', `"${top.domain}" looks similar to "${top.brand}" (edit distance: ${top.distance}).`, 'impersonation');
  }

  const digitRatio = (sld.match(/\d/g) || []).length / Math.max(sld.length, 1);
  if (digitRatio > 0.3 && sld.length > 4) {
    add(10, 'medium', 'High number of digits in domain', 'Random digit-heavy domains are often used in scams.', 'domain');
  }

  if (parsed.port && !['80', '443', ''].includes(String(parsed.port))) {
    add(8, 'low', 'Non-standard port', `Using port ${parsed.port}, which is uncommon for public websites.`, 'transport');
  }

  const suspiciousParams = ['redirect', 'redirect_uri', 'return_url', 'next', 'url', 'continue', 'goto'];
  const paramHits = [...parsed.searchParams.keys()].filter((k) =>
    suspiciousParams.includes(k.toLowerCase())
  );
  if (paramHits.length > 0) {
    add(8, 'low', 'Open redirect parameters', `Query params: ${paramHits.join(', ')} — may redirect to external sites.`, 'obfuscation');
  }

  let dnsResult = { resolved: false, addresses: [], isPrivate: false };
  try {
    const addresses = await dns.resolve4(parsed.hostname).catch(() => dns.resolve6(parsed.hostname));
    const isPrivate = addresses.some(isPrivateIp);
    dnsResult = { resolved: true, addresses: addresses.slice(0, 3), isPrivate };
    if (isPrivate) {
      add(25, 'high', 'Resolves to private/local IP', 'The domain points to a private network address — highly suspicious for public links.', 'domain');
    }
  } catch {
    add(20, 'high', 'Domain does not resolve', 'The hostname could not be resolved via DNS.', 'domain');
  }

  let sslResult = null;
  if (parsed.protocol === 'https:' && !isIpAddress(parsed.hostname)) {
    sslResult = await checkSsl(parsed.hostname);
    if (sslResult.error) {
      add(12, 'medium', 'SSL certificate check failed', sslResult.error, 'transport');
    } else if (sslResult.isExpired) {
      add(20, 'high', 'Expired SSL certificate', `Certificate expired on ${new Date(sslResult.validTo).toLocaleDateString()}.`, 'transport');
    } else if (sslResult.isSelfSigned) {
      add(18, 'high', 'Self-signed SSL certificate', 'No trusted certificate authority issued this certificate.', 'transport');
    } else if (!sslResult.coversHost) {
      add(22, 'high', 'SSL certificate mismatch', `Certificate issued for "${sslResult.subject}" does not match "${parsed.hostname}".`, 'transport');
    } else if (sslResult.daysRemaining < 7) {
      add(5, 'low', 'SSL certificate expiring soon', `Expires in ${sslResult.daysRemaining} day(s).`, 'transport');
    }
  }

  const hasCritical = checks.some((c) => c.severity === 'critical');
  const hasHigh = checks.some((c) => c.severity === 'high');

  let verdict;
  if (riskScore >= 60 || hasCritical) verdict = 'phishing';
  else if (riskScore >= 30 || hasHigh) verdict = 'suspicious';
  else if (riskScore >= 10) verdict = 'caution';
  else verdict = 'safe';

  return buildResult(
    rawInput, normalized, parsed, checks,
    Math.min(riskScore, 100), verdict, dnsResult, sslResult, expandResult
  );
}

function buildResult(rawInput, normalized, parsed, checks, riskScore, verdict, dnsResult, sslResult, expandResult) {
  const verdictMeta = {
    safe: { label: 'Likely Safe', color: '#22c55e', icon: 'shield-check' },
    caution: { label: 'Use Caution', color: '#eab308', icon: 'shield-alert' },
    suspicious: { label: 'Suspicious', color: '#f97316', icon: 'shield-warning' },
    phishing: { label: 'Likely Phishing', color: '#ef4444', icon: 'shield-x' },
  };

  const meta = verdictMeta[verdict] || verdictMeta.caution;

  return {
    input: rawInput,
    normalizedUrl: normalized,
    analyzedUrl: parsed.href,
    domain: parsed.hostname,
    protocol: parsed.protocol.replace(':', ''),
    path: parsed.pathname,
    query: parsed.search || '',
    riskScore,
    verdict,
    verdictLabel: meta.label,
    verdictColor: meta.color,
    verdictIcon: meta.icon,
    checks: checks.sort((a, b) => b.score - a.score),
    categories: buildCategories(checks),
    recommendations: RECOMMENDATIONS[verdict] || RECOMMENDATIONS.caution,
    dns: dnsResult,
    ssl: sslResult,
    expansion: expandResult,
    analyzedAt: new Date().toISOString(),
  };
}

module.exports = { analyzeUrl };

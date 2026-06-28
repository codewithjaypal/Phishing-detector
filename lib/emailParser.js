const URL_REGEX = /https?:\/\/[^\s<>"')\]},]+/gi;

function extractUrls(text) {
  const matches = text.match(URL_REGEX) || [];
  return [...new Set(matches.map((u) => u.replace(/[.,;:!?)]+$/, '')))];
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  return [...new Set(text.match(emailRegex) || [])];
}

function analyzeEmailContent(text) {
  const urls = extractUrls(text);
  const senderEmails = extractEmails(text);
  const suspiciousPhrases = [
    'urgent action required', 'verify your account', 'suspended', 'click here immediately',
    'confirm your identity', 'unusual activity', 'wire transfer', 'gift card',
    'act now', 'within 24 hours', 'password expired', 'security alert',
  ];

  const lower = text.toLowerCase();
  const phraseHits = suspiciousPhrases.filter((p) => lower.includes(p));

  return {
    urls,
    senderEmails,
    phraseHits,
    urlCount: urls.length,
    hasSuspiciousLanguage: phraseHits.length > 0,
  };
}

module.exports = { extractUrls, extractEmails, analyzeEmailContent };

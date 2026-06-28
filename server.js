const express = require('express');
const path = require('path');
const { analyzeUrl } = require('./lib/analyzer');
const { analyzeEmailContent } = require('./lib/emailParser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/analyze', async (req, res) => {
  const { url, expandShortUrls = true } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required.' });
  }

  try {
    const result = await analyzeUrl(url, { expandShortUrls });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Analysis failed.' });
  }
});

app.post('/api/analyze-email', async (req, res) => {
  const { content } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Email content is required.' });
  }

  try {
    const emailMeta = analyzeEmailContent(content);
    const urlResults = [];

    for (const url of emailMeta.urls.slice(0, 10)) {
      try {
        const result = await analyzeUrl(url);
        urlResults.push(result);
      } catch (err) {
        urlResults.push({ input: url, error: err.message, verdict: 'error' });
      }
    }

    const worstVerdict = urlResults.reduce((worst, r) => {
      const order = { phishing: 4, suspicious: 3, caution: 2, safe: 1, error: 0 };
      return (order[r.verdict] || 0) > (order[worst] || 0) ? r.verdict : worst;
    }, 'safe');

    const maxScore = urlResults.reduce((max, r) => Math.max(max, r.riskScore || 0), 0);

    res.json({
      emailMeta,
      urlResults,
      overallVerdict: emailMeta.hasSuspiciousLanguage && maxScore >= 30 ? 'phishing' : worstVerdict,
      overallScore: maxScore,
      analyzedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Email analysis failed.' });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '2.0' });
});

app.listen(PORT, () => {
  console.log(`PhishGuard running at http://localhost:${PORT}`);
});

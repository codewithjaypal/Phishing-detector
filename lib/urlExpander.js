const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 's.id', 'v.gd', 'clck.ru',
  'tiny.cc', 'soo.gd', 'bc.vc', 'adf.ly', 'j.mp', 'dlvr.it', 'lnkd.in',
  'shorte.st', 'ouo.io', 'linktr.ee', 't.ly',
]);

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT = 8000;

function isShortener(hostname) {
  const host = hostname.toLowerCase().replace(/^www\./, '');
  return SHORTENER_DOMAINS.has(host) ||
    SHORTENER_DOMAINS.has(host.split('.').slice(-2).join('.'));
}

async function expandUrl(rawUrl) {
  const chain = [{ url: rawUrl, status: null }];
  let current = rawUrl;

  for (let i = 0; i < MAX_REDIRECTS; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    try {
      const res = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'PhishGuard/1.0 (Security Scanner)' },
      });

      chain[chain.length - 1].status = res.status;

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get('location');
        if (!location) break;

        const next = new URL(location, current).href;
        chain.push({ url: next, status: null });
        current = next;
        continue;
      }
      break;
    } catch (err) {
      chain[chain.length - 1].error = err.name === 'AbortError' ? 'timeout' : 'unreachable';
      break;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    original: rawUrl,
    final: current,
    expanded: current !== rawUrl,
    hops: chain.length - 1,
    chain,
  };
}

module.exports = { isShortener, expandUrl, SHORTENER_DOMAINS };

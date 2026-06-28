const tls = require('tls');

const CHECK_TIMEOUT = 6000;

function checkSsl(hostname, port = 443) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ valid: false, error: 'Connection timed out' });
    }, CHECK_TIMEOUT);

    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !Object.keys(cert).length) {
          resolve({ valid: false, error: 'No certificate returned' });
          return;
        }

        const now = Date.now();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo;
        const isSelfSigned = cert.issuer && cert.subject &&
          JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

        const altNames = (cert.subjectaltname || '')
          .split(', ')
          .filter((n) => n.startsWith('DNS:'))
          .map((n) => n.replace('DNS:', ''));

        const coversHost = altNames.some(
          (name) =>
            name === hostname ||
            (name.startsWith('*.') && hostname.endsWith(name.slice(1)))
        ) || cert.subject?.CN === hostname;

        resolve({
          valid: !isExpired && coversHost,
          issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          subject: cert.subject?.CN || hostname,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysRemaining,
          isExpired,
          isSelfSigned,
          coversHost,
          altNames: altNames.slice(0, 5),
        });
      }
    );

    socket.on('error', (err) => {
      clearTimeout(timer);
      resolve({ valid: false, error: err.message });
    });
  });
}

module.exports = { checkSsl };

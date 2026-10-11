// Site HTTPS local de test pour l'extension : plusieurs types de formulaires de login.
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.E2E_PORT || 8443);
const SITE = path.join(__dirname, 'site');
const submissions = [];

const server = https.createServer({
  key: fs.readFileSync(path.join(__dirname, 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
}, (req, res) => {
  const url = new URL(req.url, 'https://localhost');
  if (req.method === 'POST' && url.pathname === '/submit') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { submissions.push(JSON.parse(body)); } catch { submissions.push({ raw: body }); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    return;
  }
  if (url.pathname === '/__submissions') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(submissions));
    return;
  }
  const file = path.join(SITE, url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\//, ''));
  if (!file.startsWith(SITE) || !fs.existsSync(file)) {
    res.writeHead(404); res.end('not found'); return;
  }
  res.writeHead(200, { 'Content-Type': file.endsWith('.js') ? 'application/javascript' : 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(file));
});

server.listen(PORT, '127.0.0.1', () => console.log('E2E site on https://localhost:' + PORT));

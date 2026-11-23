// Prévisualisation du build avec la CSP EXACTE du Caddyfile (pour détecter toute violation). Dev uniquement.
// Usage : node dev/csp-preview.mjs   (sert dist/ sur 5180 ; /api -> mock sur 8787)
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'

const caddy = fs.readFileSync(path.resolve('../proxy/Caddyfile'), 'utf8')
const CSP = caddy.match(/header Content-Security-Policy "([^"]+)"/)[1]
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }

http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    const up = http.request({ host: '127.0.0.1', port: 8787, path: req.url, method: req.method, headers: req.headers }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res) })
    req.pipe(up)
    return
  }
  let f = path.join('dist', req.url.split('?')[0])
  if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join('dist', 'index.html')
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff' })
  fs.createReadStream(f).pipe(res)
}).listen(5180, '127.0.0.1', () => console.log('CSP preview http://127.0.0.1:5180\nCSP =', CSP))

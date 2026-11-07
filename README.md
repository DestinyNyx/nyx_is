require('fs').existsSync('.env') && require('fs').readFileSync('.env','utf8').split('\n').forEach(l=>{
  const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
});

const express = require('express');
const session = require('express-session');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const {
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN,
  REDIRECT_URI, SESSION_SECRET, ADMIN_KEY
} = process.env;
const PORT = process.env.PORT || 3000;

const sessionMw = session({
  secret: SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
});
app.use(express.json());
app.use(sessionMw);
io.engine.use(sessionMw);

// ---------- Códigos de acesso (uso único, 5 minutos) ----------
const codes = new Map();        // userId -> { code, expires }
const blocked = new Set();      // userIds bloqueados pelo admin
const online = new Map();       // socket.id -> { id, name, avatar }
const CODE_TTL = 5 * 60 * 1000;

function newCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

async function discordFetch(url, options) {
  const r = await fetch(url, options);
  if (!r.ok) throw new Error('Discord ' + r.status + ' ' + (await r.text()));
  return r.json();
}

async function sendDM(userId, text) {
  const headers = { Authorization: 'Bot ' + DISCORD_BOT_TOKEN, 'Content-Type': 'application/json' };
  const ch = await discordFetch('https://discord.com/api/v10/users/@me/channels', {
    method: 'POST', headers, body: JSON.stringify({ recipient_id: userId })
  });
  await discordFetch('https://discord.com/api/v10/channels/' + ch.id + '/messages', {
    method: 'POST', headers, body: JSON.stringify({ content: text })
  });
}

// ---------- Login com Discord ----------
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const url = 'https://discord.com/oauth2/authorize?' + new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state
  });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || state !== req.session.oauthState) return res.status(400).send('Login inválido.');
    const token = await discordFetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code, redirect_uri: REDIRECT_URI
      })
    });
    const user = await discordFetch('https://discord.com/api/users/@me', {
      headers: { Authorization: 'Bearer ' + token.access_token }
    });
    req.session.pending = {
      id: user.id,
      name: user.global_name || user.username,
      avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : null
    };
    req.session.verified = false;
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Erro ao entrar com o Discord.');
  }
});

app.get('/api/me', (req, res) => {
  const p = req.session.pending;
  res.json({ logged: !!p, verified: !!req.session.verified, user: p || null });
});

// Pedir código novo (enviado por mensagem direta no Discord)
app.post('/api/request-code', async (req, res) => {
  const p = req.session.pending;
  if (!p) return res.status(401).json({ error: 'Faça login com o Discord primeiro.' });
  if (blocked.has(p.id)) return res.status(403).json({ error: 'Você está bloqueado.' });
  const c = newCode();
  codes.set(p.id, { code: c, expires: Date.now() + CODE_TTL });
  try {
    await sendDM(p.id, `Seu código de acesso ao Nyx Community: **${c}**\nVale por 5 minutos e só funciona uma vez.`);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Não consegui mandar DM. Entre no servidor do bot e libere mensagens diretas.' });
  }
});

// Confirmar código
app.post('/api/verify-code', (req, res) => {
  const p = req.session.pending;
  if (!p) return res.status(401).json({ error: 'Faça login primeiro.' });
  const entry = codes.get(p.id);
  const typed = String((req.body && req.body.code) || '').trim();
  if (!entry || Date.now() > entry.expires) return res.status(400).json({ error: 'Código expirado. Peça outro.' });
  if (entry.code !== typed) return res.status(400).json({ error: 'Código errado.' });
  codes.delete(p.id); // uso único
  req.session.verified = true;
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// ---------- Painel do administrador ----------
function adminOnly(req, res, next) {
  if (req.get('x-admin-key') !== ADMIN_KEY) return res.status(403).json({ error: 'Chave inválida.' });
  next();
}
app.get('/api/admin/online', adminOnly, (req, res) => {
  res.json({ online: [...online.values()], blocked: [...blocked] });
});
app.post('/api/admin/block', adminOnly, (req, res) => {
  const id = String(req.body.id || '');
  blocked.add(id);
  for (const [sid, u] of online) if (u.id === id) io.sockets.sockets.get(sid)?.disconnect(true);
  res.json({ ok: true });
});
app.post('/api/admin/unblock', adminOnly, (req, res) => {
  blocked.delete(String(req.body.id || ''));
  res.json({ ok: true });
});

// ---------- Call (sinalização WebRTC + chat) ----------
const ROOM = 'call-unica';

io.use((socket, next) => {
  const s = socket.request.session;
  if (!s || !s.verified || !s.pending || blocked.has(s.pending.id)) return next(new Error('não autorizado'));
  socket.user = s.pending;
  next();
});

io.on('connection', (socket) => {
  online.set(socket.id, socket.user);
  socket.join(ROOM);

  const others = [...online.entries()].filter(([id]) => id !== socket.id)
    .map(([id, u]) => ({ socketId: id, ...u }));
  socket.emit('peers', others);
  socket.to(ROOM).emit('peer-joined', { socketId: socket.id, ...socket.user });

  socket.on('signal', ({ to, data }) => {
    io.to(to).emit('signal', { from: socket.id, data });
  });
  socket.on('chat', (text) => {
    const msg = String(text || '').slice(0, 500);
    if (msg) io.to(ROOM).emit('chat', { name: socket.user.name, text: msg, at: Date.now() });
  });

  socket.on('disconnect', () => {
    online.delete(socket.id);
    socket.to(ROOM).emit('peer-left', { socketId: socket.id });
  });
});

app.use(express.static('public'));
server.listen(PORT, () => console.log('Nyx Community rodando na porta ' + PORT));

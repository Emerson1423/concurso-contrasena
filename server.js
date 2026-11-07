'use strict';
/*
  Concurso "la contraseña más segura".
  - Los docentes se registran con su nombre y una contraseña INVENTADA (/).
  - Cada contraseña se evalúa al instante con zxcvbn, pero los resultados se ocultan hasta que el instructor avance (/admin).
  - La contraseña en texto solo se guarda en memoria si la persona aceptó que se muestre si queda en el top 2.
  - Fases: registro > cerrado (predicciones) > resultados > top2 > ganador.
  - Todo vive en memoria: si el servidor se reinicia, el concurso vuelve a cero.
*/
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const { WebSocketServer } = require('ws');
const zxcvbn = require('zxcvbn');

const PORT = process.env.PORT || 3000;
const KEY = process.env.INSTRUCTOR_KEY || 'instructor';
if (!process.env.INSTRUCTOR_KEY) {
  console.warn('[aviso] INSTRUCTOR_KEY no está definida. Se usa "instructor". Cámbiala antes de desplegar.');
}

// Lista de contraseñas y patrones comunes (lo que probaría un atacante primero)
const COMMON = ['123456', 'password', '12345678', 'qwerty', 'abc123', '111111', '123456789', 'iloveyou', 'admin', 'letmein', 'contraseña', 'universidad', 'colegio01', 'docente', 'dios123', 'elsalvador', '123123', 'sansalvador', '1234567890', 'maria2024', 'qwerty123', '12345', '1234', '000000', 'password1', 'contraseña1', 'bienvenido', 'bienvenida', 'maestro', 'maestra', 'profesor', 'profesora', 'escuela', 'colegio'];
const BASES = ['maria', 'jose', 'carlos', 'ana', 'luis', 'carmen', 'juan', 'rosa', 'miguel', 'sofia', 'pedro', 'lucia', 'roberto', 'daniela', 'fernando', 'colegio', 'docente', 'ugb', 'escuela', 'profesor', 'admin', 'password', 'dios', 'amor'];
const dict = new Set(COMMON);
for (const b of BASES) {
  for (const c of [b, b[0].toUpperCase() + b.slice(1)]) {
    for (let y = 1970; y <= 2026; y++) { dict.add(c + y); dict.add(c + y + '!'); dict.add(c + '.' + y + '!'); dict.add(c + '#' + y); dict.add(c + y + '.'); }
  }
}

const PHASES = ['registro', 'cerrado', 'resultados', 'top2', 'ganador'];
let phase = 'registro';
const parts = new Map();      // id -> { id, name, consent, pass, ev, token }
const tokens = new Map();     // token -> id
const predMap = new Map();    // speakerId -> { speakerId, pickId, why }
const sockets = new Map();    // id -> Set(ws)
const admins = new Set();

const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const strip = (s) => String(s).normalize('NFD').replace(/[\u0300-\u036f]/g, '');
const clean = (n) => String(n || '').replace(/\s+/g, ' ').trim().slice(0, 40);

function human(g10) {
  const s = Math.pow(10, g10 - 10); // suponiendo 10 mil millones de intentos por segundo
  if (!(s >= 1)) return 'menos de un segundo';
  const f = (n, u, p) => { n = Math.round(n); return n + ' ' + (n === 1 ? u : p); };
  const y = 31557600;
  if (s < 60) return f(s, 'segundo', 'segundos');
  if (s < 3600) return f(s / 60, 'minuto', 'minutos');
  if (s < 86400) return f(s / 3600, 'hora', 'horas');
  if (s < y) return f(s / 86400, 'día', 'días');
  if (s < y * 1e3) return f(s / y, 'año', 'años');
  if (s < y * 1e6) return 'miles de años';
  if (s < y * 1e9) return 'millones de años';
  return 'miles de millones de años o más';
}

function evaluate(name, pass) {
  const nameParts = strip(name).toLowerCase().split(/\s+/).filter((w) => w.length >= 3);
  const r = zxcvbn(pass, nameParts);
  const low = strip(pass).toLowerCase();
  const feats = {
    len: pass.length,
    upper: /[A-ZÁÉÍÓÚÑ]/.test(pass),
    digit: /\d/.test(pass),
    symbol: /[^A-Za-zÀ-ÿ0-9\s]/.test(pass),
    words: pass.split(/[^A-Za-zÀ-ÿ0-9]+/).filter((w) => w.length >= 2).length,
    hasName: nameParts.some((w) => low.includes(w)),
    inDict: dict.has(pass) || dict.has(pass.toLowerCase()),
  };
  return { g10: r.guesses_log10, score: r.score, feats, time: feats.inDict ? 'unos segundos' : human(r.guesses_log10) };
}

function facts(ev) {
  const f = ev.feats, t = [f.len + ' caracteres'];
  if (f.words >= 2) t.push(f.words + ' palabras');
  t.push(f.inDict ? 'Está en las listas comunes' : 'No está en las listas comunes');
  t.push(f.hasName ? 'Incluye su nombre' : 'No incluye su nombre');
  const kinds = [f.upper && 'mayúsculas', f.digit && 'números', f.symbol && 'símbolos'].filter(Boolean);
  if (kinds.length) t.push('Usa ' + kinds.join(', '));
  return t;
}

function tips(ev) {
  const f = ev.feats, t = [];
  if (f.inDict) t.push('Estaba en las listas de claves y patrones comunes.');
  if (f.hasName) t.push('Incluía tu nombre, y eso es lo primero que prueba un atacante.');
  if (f.len < 12) t.push('Era corta: cada carácter extra multiplica el trabajo del atacante.');
  if (ev.score <= 1 && !f.inDict) t.push('Tiene un patrón muy predecible (repeticiones o secuencias), aunque no esté en las listas.');
  if (ev.score >= 3 && f.words >= 4 && f.len >= 16) t.push('Es una frase larga de varias palabras: difícil de adivinar y fácil de recordar.');
  else if (ev.score >= 3 && f.len >= 16) t.push('Su largo ayuda mucho.');
  if (ev.score >= 3 && !f.inDict && !f.hasName && f.len >= 12) t.push('No aparece en listas comunes ni usa datos personales obvios.');
  return t;
}

function ranking() {
  const arr = [...parts.values()].filter((p) => p.ev);
  arr.sort((a, b) => (Number(a.ev.feats.inDict) - Number(b.ev.feats.inDict)) || (b.ev.g10 - a.ev.g10) || (b.ev.feats.len - a.ev.feats.len) || a.name.localeCompare(b.name));
  arr.forEach((p, i) => { p.rank = i + 1; });
  return arr;
}
const idx = () => PHASES.indexOf(phase);
const nameOf = (id) => (parts.get(id) ? parts.get(id).name : '—');

function finalist(p, showPass) {
  return { rank: p.rank, name: p.name, time: p.ev.time, facts: facts(p.ev), pass: showPass && p.consent ? p.pass : null, consent: p.consent };
}

function participantState(p) {
  const st = { t: 'c_state', phase, me: { id: p.id, name: p.name, consent: p.consent } };
  if (idx() >= 3) {
    const r = ranking();
    st.total = r.length;
    st.top2 = r.slice(0, 2).map((x) => ({ rank: x.rank, name: x.name }));
    st.mine = { rank: p.rank, time: p.ev.time, tips: tips(p.ev) };
    if (phase === 'ganador') st.finalists = r.slice(0, 2).map((x) => finalist(x, true));
  }
  return st;
}

function adminState() {
  const showEv = idx() >= 2;
  const r = showEv ? ranking() : [];
  const rankOf = new Map(r.map((p) => [p.id, p.rank]));
  const list = [...parts.values()].map((p) => ({
    id: p.id, name: p.name, consent: p.consent, online: (sockets.get(p.id) || new Set()).size > 0,
    rank: showEv ? rankOf.get(p.id) : null,
    ev: showEv ? { time: p.ev.time, inDict: p.ev.feats.inDict, len: p.ev.feats.len, words: p.ev.feats.words, hasName: p.ev.feats.hasName } : null,
  }));
  const preds = [...predMap.values()].map((x) => ({
    speakerId: x.speakerId, speaker: nameOf(x.speakerId), pickId: x.pickId, pick: nameOf(x.pickId), why: x.why,
    win: showEv && r[0] ? r[0].id === x.pickId : null,
    top2: showEv ? r.slice(0, 2).some((p) => p.id === x.pickId) : null,
  }));
  return {
    t: 'c_admin', phase, parts: list, preds,
    summary: showEv ? { win: preds.filter((p) => p.win).length, top2: preds.filter((p) => p.top2).length, total: preds.length } : null,
    podium: idx() >= 3 ? r.slice(0, 2).map((x) => finalist(x, phase === 'ganador')) : null,
  };
}

function pushAll() {
  admins.forEach((ws) => send(ws, adminState()));
  parts.forEach((p) => (sockets.get(p.id) || []).forEach((ws) => send(ws, participantState(p))));
}

function reset() {
  phase = 'registro';
  parts.forEach((p) => (sockets.get(p.id) || []).forEach((ws) => ws.close(4003)));
  parts.clear(); tokens.clear(); predMap.clear(); sockets.clear();
  pushAll();
}

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.post('/api/register', (req, res) => {
  if (phase !== 'registro') return res.status(409).json({ error: 'El registro ya está cerrado' });
  const name = clean((req.body || {}).name);
  const pass = (req.body || {}).pass;
  if (!name) return res.status(400).json({ error: 'Escribe tu nombre' });
  if (typeof pass !== 'string' || !pass.length || pass.length > 100) return res.status(400).json({ error: 'Escribe una contraseña (máximo 100 caracteres)' });
  if (parts.size >= 60) return res.status(429).json({ error: 'Ya se alcanzó el máximo de participantes' });
  if ([...parts.values()].some((p) => p.name.toLowerCase() === name.toLowerCase())) return res.status(409).json({ error: 'Ese nombre ya está registrado. Agrega tu apellido.' });
  const consent = !!(req.body || {}).consent;
  const id = crypto.randomBytes(4).toString('hex'), token = crypto.randomBytes(16).toString('hex');
  parts.set(id, { id, name, consent, pass: consent ? pass : null, ev: evaluate(name, pass), token });
  tokens.set(token, id);
  pushAll();
  res.json({ token, id, name });
});

app.post('/api/update', (req, res) => {
  const p = parts.get(tokens.get((req.body || {}).token));
  if (!p) return res.status(401).json({ error: 'Sesión no válida' });
  if (phase !== 'registro') return res.status(409).json({ error: 'El registro ya está cerrado' });
  const pass = req.body.pass;
  if (typeof pass !== 'string' || !pass.length || pass.length > 100) return res.status(400).json({ error: 'Escribe una contraseña (máximo 100 caracteres)' });
  p.consent = !!req.body.consent; p.pass = p.consent ? pass : null; p.ev = evaluate(p.name, pass);
  pushAll();
  res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  if (q.get('role') === 'admin') {
    if (q.get('key') !== KEY) { ws.close(4001); return; }
    admins.add(ws);
    send(ws, adminState());
    ws.on('message', (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (m.t === 'c_cmd') {
        if (m.cmd === 'next') {
          if (phase === 'registro' && parts.size < 1) return;
          if (idx() < PHASES.length - 1) phase = PHASES[idx() + 1];
        } else if (m.cmd === 'back') { if (idx() > 0) phase = PHASES[idx() - 1]; }
        else if (m.cmd === 'reset') { reset(); return; }
        pushAll();
      } else if (m.t === 'c_pred') {
        if (!parts.has(m.speakerId) || !parts.has(m.pickId)) return;
        predMap.set(m.speakerId, { speakerId: m.speakerId, pickId: m.pickId, why: String(m.why || '').trim().slice(0, 200) });
        admins.forEach((a) => send(a, adminState()));
      } else if (m.t === 'c_pred_del') {
        predMap.delete(m.speakerId);
        admins.forEach((a) => send(a, adminState()));
      }
    });
    ws.on('close', () => admins.delete(ws));
    return;
  }

  const p = parts.get(tokens.get(q.get('token')));
  if (!p) { ws.close(4002); return; }
  if (!sockets.has(p.id)) sockets.set(p.id, new Set());
  sockets.get(p.id).add(ws);
  send(ws, participantState(p));
  admins.forEach((a) => send(a, adminState()));
  ws.on('close', () => { if (sockets.has(p.id)) sockets.get(p.id).delete(ws); admins.forEach((a) => send(a, adminState())); });
});

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false; ws.ping();
  });
}, 25000);

server.listen(PORT, () => console.log('Concurso escuchando en el puerto ' + PORT));

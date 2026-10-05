// TaknaPay License Server - runs ONLY on your side. Resellers' scripts call it over HTTPS.
// MongoDB credentials and the private signing key never leave this server.
// load .env when running locally (on Render/hosts, set these as environment variables instead)
try { require('fs').readFileSync(require('path').join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => { const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(l); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, ''); }); } catch (e) {}
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PRIVATE_KEY = (process.env.LICENSE_PRIVATE_KEY || '').replace(/\\n/g, '\n') ||
    (fs.existsSync(path.join(__dirname, 'private.pem')) ? fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8') : '');
const ADMIN_KEY = process.env.LICENSE_ADMIN_KEY || '';
if (!process.env.MONGO_URI || !PRIVATE_KEY || ADMIN_KEY.length < 16) {
    console.error('Set MONGO_URI, LICENSE_ADMIN_KEY (16+ chars) and the private key (private.pem or LICENSE_PRIVATE_KEY).');
    process.exit(1);
}
const TOKEN_DAYS = 7; // the reseller script must re-verify within this window (it does so every 6 hours)

mongoose.connect(process.env.MONGO_URI).then(() => console.log('MongoDB connected'), e => { console.error(e.message); process.exit(1); });
const License = mongoose.model('License', new mongoose.Schema({
    keyHash: { type: String, unique: true, index: true },
    codeHash: String,
    keyHint: String,           // last 4 chars only, for your reference
    buyer: String,
    maxDomains: { type: Number, default: 1 },
    domains: [String],
    status: { type: String, default: 'ACTIVE' }, // ACTIVE | REVOKED
    expiresAt: { type: Date, default: null },     // null = lifetime
    lastSeen: Date, lastIp: String,
    createdAt: { type: Date, default: Date.now }
}));

// Update releases: you upload a bundle (made by scripts/build-release.js), resellers can choose to install it.
const Release = mongoose.model('Release', new mongoose.Schema({
    version: { type: String, unique: true },
    notes: String,
    sha256: String,
    size: Number,
    data: Buffer,               // the bundle itself (.gz)
    requiresInstall: { type: Boolean, default: false },
    published: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
}));
const verParts = v => String(v).split('.').map(n => parseInt(n, 10) || 0);
const newer = (a, b) => { const x = verParts(a), y = verParts(b); for (let i = 0; i < 4; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); } return false; };
async function latestRelease() {
    const all = await Release.find({ published: true }).select('-data').lean();
    return all.sort((a, b) => newer(a.version, b.version) ? -1 : 1)[0] || null;
}

const h = v => crypto.createHash('sha256').update('tkp-lic:' + String(v).trim().toUpperCase()).digest('hex');
const sign = payload => { const s = JSON.stringify(payload); return { payload: s, sig: crypto.sign(null, Buffer.from(s), PRIVATE_KEY).toString('base64') }; };
const cleanDomain = d => String(d || '').toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/^www\./, '').slice(0, 100);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '5kb' }));

const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
const limit = max => (req, res, next) => { const k = req.ip; const n = (hits.get(k) || 0) + 1; hits.set(k, n); n > max ? res.status(429).json({ ok: false, reason: 'Too many requests' }) : next(); };

function grant(lic, domain, nonce) {
    const now = Date.now();
    let exp = now + TOKEN_DAYS * 864e5;
    if (lic.expiresAt) exp = Math.min(exp, lic.expiresAt.getTime());
    return { ok: true, ...sign({ id: String(lic._id), d: domain, n: String(nonce), iat: now, exp }) };
}
async function check(body, ip, needCode) {
    const key = String(body.key || ''), domain = cleanDomain(body.domain), nonce = String(body.nonce || '');
    if (key.length < 8 || key.length > 60 || !domain || nonce.length < 16 || nonce.length > 80) return { err: 'Invalid request' };
    const lic = await License.findOne({ keyHash: h(key) });
    if (!lic || (needCode && lic.codeHash !== h(body.code || ''))) return { err: 'Invalid purchase key or activation code' };
    if (lic.status !== 'ACTIVE') return { err: 'This license has been revoked', revoked: true };
    if (lic.expiresAt && lic.expiresAt < new Date()) return { err: 'This license has expired', revoked: true };
    return { lic, domain, nonce };
}

app.post('/api/license/activate', limit(20), async (req, res) => {
    try {
        const r = await check(req.body, req.ip, true);
        if (r.err) return res.status(403).json({ ok: false, reason: r.err, revoked: !!r.revoked });
        const { lic, domain, nonce } = r;
        if (!lic.domains.includes(domain)) {
            if (lic.domains.length >= lic.maxDomains) return res.status(403).json({ ok: false, reason: 'This key is already used on another domain (limit ' + lic.maxDomains + '). Contact the seller.' });
            lic.domains.push(domain);
        }
        lic.lastSeen = new Date(); lic.lastIp = req.ip; await lic.save();
        res.json(grant(lic, domain, nonce));
    } catch (e) { res.status(500).json({ ok: false, reason: 'Server error' }); }
});
app.post('/api/license/verify', limit(60), async (req, res) => {
    try {
        const r = await check(req.body, req.ip, false);
        if (r.err) return res.status(403).json({ ok: false, reason: r.err, revoked: !!r.revoked });
        if (!r.lic.domains.includes(r.domain)) return res.status(403).json({ ok: false, reason: 'Domain not activated', revoked: true });
        r.lic.lastSeen = new Date(); r.lic.lastIp = req.ip; await r.lic.save();
        res.json(grant(r.lic, r.domain, r.nonce));
    } catch (e) { res.status(500).json({ ok: false, reason: 'Server error' }); }
});

// ---- your admin API (header: x-admin-key)
function admin(req, res, next) {
    const a = Buffer.from(String(req.headers['x-admin-key'] || '')), b = Buffer.from(ADMIN_KEY);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ ok: false });
    next();
}
const rnd = (n, set) => Array.from(crypto.randomBytes(n), x => set[x % set.length]).join('');
app.post('/admin/licenses', limit(30), admin, async (req, res) => {
    const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const key = 'TKP-' + [0, 1, 2, 3].map(() => rnd(4, A)).join('-'), code = rnd(8, '0123456789');
    const days = Number(req.body.days) || 0;
    const lic = await License.create({ keyHash: h(key), codeHash: h(code), keyHint: key.slice(-4), buyer: String(req.body.buyer || '').slice(0, 80),
        maxDomains: Math.min(Math.max(Number(req.body.maxDomains) || 1, 1), 20), expiresAt: days > 0 ? new Date(Date.now() + days * 864e5) : null });
    res.json({ ok: true, id: lic._id, purchaseKey: key, activationCode: code, note: 'Shown only once - send to the buyer.' });
});
app.get('/admin/licenses', admin, async (req, res) => res.json({ ok: true, licenses: await License.find().sort({ createdAt: -1 }).limit(500).select('-keyHash -codeHash').lean() }));
app.post('/admin/licenses/:id/:action', admin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ ok: false });
    const a = req.params.action;
    if (a === 'delete') { await License.deleteOne({ _id: req.params.id }); return res.json({ ok: true }); }
    const upd = a === 'revoke' ? { status: 'REVOKED' } : a === 'restore' ? { status: 'ACTIVE' } : a === 'reset-domains' ? { domains: [] } : null;
    if (!upd) return res.status(400).json({ ok: false });
    await License.updateOne({ _id: req.params.id }, upd);
    res.json({ ok: true });
});
// ---- updates (reseller side). Needs a valid, activated license. Answer is signed, so it cannot be faked.
app.post('/api/update/check', limit(60), async (req, res) => {
    try {
        const r = await check(req.body, req.ip, false);
        if (r.err) return res.status(403).json({ ok: false, reason: r.err, revoked: !!r.revoked });
        if (!r.lic.domains.includes(r.domain)) return res.status(403).json({ ok: false, reason: 'Domain not activated', revoked: true });
        const cur = String(req.body.current || '0').slice(0, 20), rel = await latestRelease();
        const now = Date.now(), base = { n: r.nonce, d: r.domain, iat: now, exp: now + 10 * 60 * 1000 };
        if (!rel || !newer(rel.version, cur)) return res.json({ ok: true, ...sign({ ...base, update: false }) });
        res.json({ ok: true, ...sign({ ...base, update: true, version: rel.version, notes: rel.notes || '', sha256: rel.sha256, size: rel.size, requiresInstall: !!rel.requiresInstall, date: rel.createdAt }) });
    } catch (e) { res.status(500).json({ ok: false, reason: 'Server error' }); }
});
app.post('/api/update/download', limit(10), async (req, res) => {
    try {
        const r = await check(req.body, req.ip, false);
        if (r.err || !r.lic.domains.includes(r.domain)) return res.status(403).json({ ok: false, reason: r.err || 'Domain not activated' });
        const rel = await Release.findOne({ version: String(req.body.version || ''), published: true });
        if (!rel) return res.status(404).json({ ok: false, reason: 'Release not found' });
        res.set('Content-Type', 'application/octet-stream').send(rel.data);
    } catch (e) { res.status(500).json({ ok: false, reason: 'Server error' }); }
});

// ---- your admin API for releases. Upload body = the .gz bundle, details in headers.
app.post('/admin/releases', limit(10), admin, express.raw({ type: '*/*', limit: '25mb' }), async (req, res) => {
    try {
        const version = String(req.headers['x-version'] || '').trim();
        if (!/^\d+\.\d+\.\d+$/.test(version)) return res.status(400).json({ ok: false, reason: 'Version must look like 1.5.0' });
        if (!Buffer.isBuffer(req.body) || req.body.length < 100) return res.status(400).json({ ok: false, reason: 'Bundle file missing' });
        if (await Release.exists({ version })) return res.status(400).json({ ok: false, reason: 'This version already exists' });
        const data = req.body, notes = decodeURIComponent(String(req.headers['x-notes'] || '')).slice(0, 2000);
        const rel = await Release.create({ version, notes, data, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex'), requiresInstall: req.headers['x-requires-install'] === '1' });
        res.json({ ok: true, id: rel._id, sha256: rel.sha256 });
    } catch (e) { res.status(500).json({ ok: false, reason: e.message }); }
});
app.get('/admin/releases', admin, async (req, res) => res.json({ ok: true, releases: await Release.find().sort({ createdAt: -1 }).limit(50).select('-data').lean() }));
app.post('/admin/releases/:id/:action', admin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ ok: false });
    const a = req.params.action;
    if (a === 'delete') await Release.deleteOne({ _id: req.params.id });
    else if (a === 'unpublish' || a === 'publish') await Release.updateOne({ _id: req.params.id }, { published: a === 'publish' });
    else return res.status(400).json({ ok: false });
    res.json({ ok: true });
});
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(process.env.PORT || 4000, () => console.log('License server running'));

// Meu Financeiro 1.3.0 — casal, com login Google e sincronização em nuvem.
// Modelo de segurança:
//  1) Login Google (Firebase Auth): só os e-mails listados nas regras do Firestore entram.
//  2) Senha do casal: deriva a chave AES-256-GCM (PBKDF2-SHA-256, 310 mil iterações) no próprio aparelho.
//     O servidor guarda apenas texto cifrado. A chave fica no IndexedDB do aparelho como CryptoKey não-exportável.
//  3) Cada documento é cifrado com AAD = identificador do documento (impede trocar documentos entre si).

const $ = id => document.getElementById(id);
const CATS = {
  expense: ['Alimentação', 'Combustível', 'Moradia', 'Contas domésticas', 'Saúde', 'Educação', 'Transporte', 'Lazer', 'Compras', 'Assinaturas', 'Impostos', 'Outros'],
  income: ['Salário', 'Renda extra', 'Vendas', 'Investimentos', 'Reembolso', 'Outros']
};
const CAT_ICON = { Alimentação: '🛒', Combustível: '⛽', Moradia: '🏠', 'Contas domésticas': '💡', Saúde: '💊', Educação: '🎓', Transporte: '🚗', Lazer: '🎉', Compras: '🛍️', Assinaturas: '🔁', Impostos: '🧾', Outros: '•', Salário: '💼', 'Renda extra': '✨', Vendas: '🏷️', Investimentos: '📈', Reembolso: '↩️' };
const money = n => Number(n || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad = n => String(n).padStart(2, '0');
const isoDate = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const today = () => isoDate(new Date());
const nowISO = () => new Date().toISOString();
const monthKey = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
const startOfWeek = d => { const x = new Date(d.getFullYear(), d.getMonth(), d.getDate()); x.setDate(x.getDate() - ((x.getDay() + 6) % 7)); return x; };
const fmtDate = iso => new Date(iso + 'T12:00:00').toLocaleDateString('pt-BR');
const fmtDay = iso => new Date(iso + 'T12:00:00').toLocaleDateString('pt-BR', { weekday: 'long', day: 'numeric', month: 'long' });
const sum = arr => arr.reduce((a, t) => a + t.amount, 0);
const newId = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
const initials = name => String(name).trim().split(/\s+/).slice(0, 2).map(w => w[0] || '').join('').toUpperCase() || '?';
const cleanText = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

function digitsToBRL(digits) {
  return (Number(digits || 0) / 100).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function parseBRL(value) {
  const digits = String(value || '').replace(/\D/g, '');
  return digits ? Number(digits) / 100 : 0;
}
function maskMoneyInput(el) {
  el.addEventListener('input', () => {
    const digits = el.value.replace(/\D/g, '').slice(0, 12);
    el.value = digits ? digitsToBRL(digits) : '';
  });
}
maskMoneyInput($('amountInput'));
$('amountInput').addEventListener('focus', e => { if (e.target.value === '0,00') e.target.value = ''; });

// ---------- Estado da aplicação ----------
const B = window.MF_BACKEND;                       // backend (Firebase ou simulador de testes)
const CFG = window.MF_CONFIG || {};
const MEMBERS = CFG.MEMBERS || {};                 // { 'email@gmail.com': 'Nome' }
const MIN_PW = 12;
const ITER = 310000;
const IDLE_MS = 10 * 60 * 1000;
const enc = new TextEncoder(), dec = new TextDecoder();

let me = null;                 // { email, name }
let cryptoKey = null;          // CryptoKey (não-exportável)
let coupleSalt = null;         // salt do casal (vem do documento 'verifier')
let people = [], txs = [], budgets = {}, budgetsAt = '';
let receiptData = '', selectedReceiptFile = null;
let txKind = 'expense', editingId = null, view = 'home';
let selectedPeriod = 'month', periodAnchor = new Date(), txLimit = 200;
let unsubscribe = null, remoteRaw = new Map(), decCache = new Map();
let idleTimer = null, failedTries = 0, lockedUntil = 0;
let vaultMode = 'setup';
let rebuildChain = Promise.resolve();

// ---------- Criptografia ----------
const cryptoReady = () => !!(window.crypto && crypto.subtle && crypto.getRandomValues && window.indexedDB);
const b64 = bytes => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
const unb64 = text => Uint8Array.from(atob(String(text)), c => c.charCodeAt(0));

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encWith(key, obj, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(obj)));
  return { i: b64(iv), c: b64(new Uint8Array(ct)) };
}
async function decWith(key, rec, aad) {
  const iv = unb64(rec.i), ct = unb64(rec.c);
  if (iv.length !== 12 || ct.length < 16) throw new Error('Documento corrompido.');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, ct);
  return JSON.parse(dec.decode(plain));
}

// Guarda a chave do casal neste aparelho (IndexedDB), para não pedir a senha a cada abertura.
const KeyStore = {
  db() {
    return new Promise((res, rej) => {
      const r = indexedDB.open('mf3', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('k');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  },
  async run(mode, fn) {
    const db = await this.db();
    return new Promise((res, rej) => {
      const tx = db.transaction('k', mode);
      const req = fn(tx.objectStore('k'));
      tx.oncomplete = () => { db.close(); res(req ? req.result : undefined); };
      tx.onerror = () => { db.close(); rej(tx.error); };
    });
  },
  async get() { try { return (await this.run('readonly', s => s.get('key'))) || null; } catch { return null; } },
  async put(k) { try { await this.run('readwrite', s => s.put(k, 'key')); } catch (e) { console.error(e); } },
  async del() { try { await this.run('readwrite', s => s.delete('key')); } catch { /* ignore */ } }
};

// ---------- Dados: documentos no servidor ----------
// verifier       -> {s (salt), i, c}  confirma a senha do casal
// config         -> {i, c, u}         pessoas + orçamentos (cifrado)
// tx_<id>        -> {i, c, u, d}      lançamento (cifrado); d=true => excluído (tombstone)
// rcp_<id>       -> {i, c}            foto do comprovante (cifrada)

function snapshot() {
  return { people: people.slice(), transactions: txs.slice(), budgets: { ...budgets }, budgetsAt };
}
function loadData(d) {
  people = d.people; txs = d.transactions; budgets = d.budgets || {}; budgetsAt = d.budgetsAt || '';
}

function validateData(data) {
  if (!data || !Array.isArray(data.people) || !Array.isArray(data.transactions) || data.people.length > 100 || data.transactions.length > 20000)
    throw new Error('Estrutura de dados inválida.');
  const cleanPeople = [...new Set(data.people.map(p => {
    if (typeof p !== 'string' || p.length > 80) throw new Error('Nome de pessoa inválido.');
    return p.trim();
  }).filter(Boolean))];
  const TEXT = ['description', 'category', 'person', 'payment', 'notes', 'merchant', 'beneficiary', 'payer', 'dueDate', 'reference', 'documentNumber', 'documentType'];
  const cleanTx = data.transactions.map(t => {
    if (!t || typeof t !== 'object' || !['income', 'expense'].includes(t.kind) || !Number.isFinite(t.amount) || t.amount <= 0 || t.amount > 1e9
      || typeof t.description !== 'string' || t.description.length > 300 || typeof t.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(t.date))
      throw new Error('Há um lançamento inválido nos dados.');
    const out = { ...t };
    TEXT.forEach(k => { if (out[k] !== undefined && (typeof out[k] !== 'string' || out[k].length > 2000)) throw new Error('Campo de texto inválido.'); });
    if (typeof out.id !== 'string' || out.id.length > 100) out.id = newId();
    if (typeof out.createdAt !== 'string') out.createdAt = nowISO();
    if (typeof out.updatedAt !== 'string') out.updatedAt = out.createdAt;
    if (out.receipt !== undefined && (typeof out.receipt !== 'string' || out.receipt.length > 8 * 1024 * 1024 || !/^data:image\/(png|jpeg|webp);base64,/i.test(out.receipt)))
      throw new Error('Comprovante inválido.');
    delete out.hasReceipt;
    return out;
  });
  const budgetsClean = {};
  if (data.budgets && typeof data.budgets === 'object') {
    for (const [cat, v] of Object.entries(data.budgets)) {
      if (CATS.expense.includes(cat) && Number.isFinite(v) && v > 0 && v < 1e9) budgetsClean[cat] = v;
    }
  }
  return { people: cleanPeople.length ? cleanPeople : ['Eu'], transactions: cleanTx, budgets: budgetsClean, budgetsAt: typeof data.budgetsAt === 'string' ? data.budgetsAt : '' };
}

// Converte um documento cifrado em lançamento / configuração, com cache por versão.
async function decCached(id, rec, aad) {
  const key = id + '|' + (rec.u || '') + '|' + (rec.i || '');
  if (decCache.has(key)) return decCache.get(key);
  const value = await decWith(cryptoKey, rec, aad);
  decCache.set(key, value);
  return value;
}

// Reconstrói o estado da tela a partir dos documentos recebidos do servidor.
function rebuildFromRemote() {
  rebuildChain = rebuildChain.catch(() => {}).then(async () => {
    const nextTx = [];
    let cfg = null;
    for (const [id, rec] of remoteRaw) {
      if (id === 'config') { cfg = await decCached(id, rec, 'mf3|config'); continue; }
      if (!id.startsWith('tx_') || rec.d) continue;
      const t = await decCached(id, rec, 'mf3|' + id);
      nextTx.push({ ...t, id: id.slice(3) });
    }
    txs = nextTx.sort((a, b) => b.date.localeCompare(a.date) || (b.createdAt || '').localeCompare(a.createdAt || ''));
    const names = [...new Set(Object.values(MEMBERS))];
    if (cfg) {
      people = cfg.people; budgets = cfg.budgets || {}; budgetsAt = cfg.budgetsAt || '';
      // quem usa o app sempre aparece na lista de pessoas
      const missing = names.filter(n => !people.includes(n));
      if (missing.length) { people = [...people, ...missing]; await saveConfig(); }
    } else {
      // primeiro uso do casal: cria a configuração com os membros
      people = names.length ? names : ['Eu']; budgets = {}; budgetsAt = '';
      await saveConfig();
    }
    renderAll();
  }).catch(err => {
    if (!(err && err.name === 'OperationError')) console.error(err);
    if (err && err.name === 'OperationError') lockApp('A senha do casal foi trocada em outro aparelho. Digite a nova senha.');
  });
  return rebuildChain;
}

function startListening() {
  stopListening();
  remoteRaw = new Map();
  unsubscribe = B.store.listen(changes => {
    for (const ch of changes) {
      if (ch.id === 'verifier') continue;
      if (ch.type === 'removed') remoteRaw.delete(ch.id);
      else remoteRaw.set(ch.id, ch.data);
    }
    rebuildFromRemote();
  }, err => {
    console.error(err);
    if (err && err.code === 'permission-denied') {
      toast('Esta conta não tem acesso a este casal.');
      signOutApp();
    } else {
      setSync('offline');
    }
  }, status => setSync(status));
}
function stopListening() {
  if (unsubscribe) { try { unsubscribe(); } catch { /* ignore */ } }
  unsubscribe = null;
  remoteRaw = new Map();
  decCache = new Map();
}

// ---------- Escrita ----------
async function saveTx(t) {
  const { receipt, ...rest } = t;
  const plain = { ...rest, hasReceipt: !!(receipt || t.hasReceipt) };
  delete plain.id;
  if (receipt) await B.store.setDoc('rcp_' + t.id, await encWith(cryptoKey, { receipt }, 'mf3|rcp_' + t.id));
  const rec = await encWith(cryptoKey, plain, 'mf3|tx_' + t.id);
  rec.u = t.updatedAt || nowISO();
  rec.d = false;
  await B.store.setDoc('tx_' + t.id, rec);
}
async function deleteTx(id) {
  await B.store.setDoc('tx_' + id, { d: true, u: nowISO() });
  try { await B.store.deleteDoc('rcp_' + id); } catch { /* sem foto */ }
}
async function saveConfig() {
  const rec = await encWith(cryptoKey, { people, budgets, budgetsAt }, 'mf3|config');
  rec.u = nowISO();
  await B.store.setDoc('config', rec);
}
async function fetchReceipt(id) {
  const rec = await B.store.getDoc('rcp_' + id);
  if (!rec) return '';
  const r = await decWith(cryptoKey, rec, 'mf3|rcp_' + id);
  return r.receipt || '';
}

// Compara o antes e o depois e grava só o que mudou.
async function pushChanges(before) {
  const beforeById = new Map(before.txs.map(t => [t.id, t]));
  const afterIds = new Set();
  const jobs = [];
  for (const t of txs) {
    afterIds.add(t.id);
    if (beforeById.get(t.id) === t) continue;
    jobs.push(saveTx(t));
  }
  for (const id of beforeById.keys()) if (!afterIds.has(id)) jobs.push(deleteTx(id));
  const cfgChanged = JSON.stringify([before.people, before.budgets, before.budgetsAt]) !== JSON.stringify([people, budgets, budgetsAt]);
  if (cfgChanged) jobs.push(saveConfig());
  await Promise.all(jobs);
}

async function commitChange(mutate) {
  if (!cryptoKey) return false;
  const before = { people: people.slice(), txs: txs.slice(), budgets: { ...budgets }, budgetsAt };
  mutate();
  try {
    await pushChanges(before);
    renderAll();
    return true;
  } catch (err) {
    console.error(err);
    people = before.people; txs = before.txs; budgets = before.budgets; budgetsAt = before.budgetsAt;
    renderAll();
    toast('Não foi possível salvar agora. A alteração foi desfeita; tente de novo.');
    return false;
  }
}

// Troca a senha do casal: recifra tudo com a nova chave e atualiza o verificador por último.
async function rotatePassphrase(newPw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const newKey = await deriveKey(newPw, salt);
  const oldKey = cryptoKey;
  stopListening();   // enquanto recifra, a escuta não pode usar a chave errada
  try {
    cryptoKey = newKey;
    for (const t of txs) {
      let receipt;
      if (t.hasReceipt && !t.receipt) receipt = await fetchReceiptWith(oldKey, t.id);
      await saveTx(receipt ? { ...t, receipt } : t);
    }
    await saveConfig();
    const ver = await encWith(newKey, { check: 'ok' }, 'mf3|verifier');
    await B.store.setDoc('verifier', { s: b64(salt), ...ver });
    coupleSalt = salt;
    await KeyStore.put(newKey);
    decCache = new Map();
    return true;
  } catch (err) {
    cryptoKey = oldKey;
    console.error(err);
    throw err;
  } finally {
    startListening();
  }
}
async function fetchReceiptWith(key, id) {
  const rec = await B.store.getDoc('rcp_' + id);
  if (!rec) return '';
  return (await decWith(key, rec, 'mf3|rcp_' + id)).receipt || '';
}

// ---------- Sessão e telas ----------
function setGate(name) {
  document.body.dataset.gate = name;
  if (name === 'app') { document.body.classList.remove('locked'); } else { document.body.classList.add('locked'); }
}
function showLogin(msg) {
  setGate('login');
  $('loginMsg').textContent = msg || 'Entre com sua conta Google. Quem não estiver na lista não consegue ver nada.';
  $('googleLogin').disabled = false;
}

function setSync(state) {
  const el = $('syncBadge');
  if (!el) return;
  const map = {
    synced: ['Sincronizado', 'ok'],
    pending: ['Enviando…', 'warn'],
    offline: ['Offline · salva ao reconectar', 'bad'],
    locked: ['Bloqueado', 'muted']
  };
  const [text, cls] = map[state] || map.synced;
  el.textContent = text;
  el.className = 'sync ' + cls;
}
window.addEventListener('online', () => setSync('pending'));
window.addEventListener('offline', () => setSync('offline'));

function showPassGate(mode, message) {
  vaultMode = mode;
  setGate('pass');
  const setup = mode === 'setup';
  $('vaultConfirmWrap').hidden = !setup;
  $('strengthWrap').hidden = !setup;
  $('vaultTitle').textContent = setup ? 'Criar senha do casal' : 'Senha do casal';
  $('vaultMessage').textContent = message || (setup
    ? `Crie uma senha de pelo menos ${MIN_PW} caracteres e combine com seu/sua parceiro(a). Ela protege os dados: sem ela ninguém lê nada, nem o Google.`
    : `Olá, ${me ? me.name : ''}. Digite a senha do casal para este aparelho.`);
  $('vaultSubmit').textContent = setup ? 'Criar e entrar' : 'Entrar';
  $('vaultSubmit').disabled = false;
  $('vaultPassword').value = ''; $('vaultConfirm').value = ''; $('vaultStatus').textContent = '';
  $('vaultPassword').setAttribute('autocomplete', setup ? 'new-password' : 'current-password');
  updateStrength();
  setTimeout(() => $('vaultPassword').focus(), 50);
}

async function startSession(user) {
  me = { email: user.email, name: MEMBERS[user.email] || user.name || user.email.split('@')[0] };
  $('whoami').textContent = me.name;
  const ver = await B.store.getDoc('verifier');
  if (!ver) return showPassGate('setup');
  coupleSalt = unb64(ver.s);
  const saved = await KeyStore.get();
  if (saved && await checkKey(saved, ver)) {
    cryptoKey = saved;
    return openApp();
  }
  await KeyStore.del();
  showPassGate('unlock');
}
async function checkKey(key, ver) {
  try { return (await decWith(key, ver, 'mf3|verifier')).check === 'ok'; } catch { return false; }
}

async function openApp() {
  setGate('app');
  renderAll();
  showView(view || 'home');
  startListening();
  setSync('pending');
  resetIdle();
}

function lockApp(message) {
  if (!cryptoKey && document.body.dataset.gate !== 'app') return;
  clearTimeout(idleTimer);
  stopListening();
  cryptoKey = null;
  KeyStore.del();
  txs = []; people = []; budgets = {}; budgetsAt = '';
  receiptData = ''; selectedReceiptFile = null; editingId = null;
  ['txModal', 'personModal', 'passModal'].forEach(id => $(id).classList.remove('show'));
  $('scanPreview').removeAttribute('src'); $('scanPreview').hidden = true;
  $('cameraFile').value = ''; $('receiptFile').value = '';
  if (me) showPassGate('unlock', message || 'Bloqueado. Digite a senha do casal para continuar.');
  else showLogin(message);
  setSync('locked');
}

async function signOutApp() {
  lockApp();
  me = null;
  try { await B.signOut(); } catch (err) { console.error(err); }
  showLogin('Você saiu da conta.');
}

const IDLE_EVENTS = ['pointerdown', 'keydown', 'touchstart'];
function resetIdle() {
  clearTimeout(idleTimer);
  if (cryptoKey) idleTimer = setTimeout(() => lockApp('Bloqueado por inatividade. Digite a senha do casal para continuar.'), IDLE_MS);
}
IDLE_EVENTS.forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));

// Força da senha (estimativa simples)
function strengthOf(pw) {
  let score = 0;
  if (pw.length >= MIN_PW) score++;
  if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  if (pw.length >= 20 || (pw.length >= 12 && new Set(pw).size >= 9)) score++;
  return Math.min(score, 4);
}
function updateStrength() {
  const pw = $('vaultPassword').value, cf = $('vaultConfirm').value;
  const s = strengthOf(pw);
  const labels = ['Muito fraca', 'Fraca', 'Razoável', 'Boa', 'Forte'];
  const colors = ['#ff5f75', '#ff5f75', '#ffb547', '#3fd6c4', '#3ddc97'];
  const bar = $('strengthBar');
  bar.style.width = (pw ? Math.max(8, s * 25) : 0) + '%';
  bar.style.background = colors[s];
  $('strengthText').textContent = pw ? `${labels[s]} · ${pw.length} caracteres${pw.length < MIN_PW ? ` (mínimo ${MIN_PW})` : ''}` : '';
  if (vaultMode === 'setup') {
    $('confirmText').textContent = !cf ? 'Digite a senha novamente.' : cf === pw ? '✓ As senhas conferem.' : 'As senhas ainda não conferem.';
    $('confirmText').className = 'hint ' + (!cf ? '' : cf === pw ? 'ok' : 'error');
  }
}
$('vaultPassword').addEventListener('input', updateStrength);
$('vaultConfirm').addEventListener('input', updateStrength);
$('togglePass').onclick = () => {
  const show = $('vaultPassword').type === 'password';
  $('vaultPassword').type = show ? 'text' : 'password';
  $('vaultConfirm').type = show ? 'text' : 'password';
  $('togglePass').textContent = show ? 'Ocultar' : 'Mostrar';
  $('togglePass').setAttribute('aria-pressed', String(show));
};

// Login
$('googleLogin').onclick = async () => {
  $('googleLogin').disabled = true;
  $('loginMsg').textContent = 'Abrindo o login do Google…';
  try {
    await B.signIn();
    // o retorno chega por onAuth
  } catch (err) {
    console.error(err);
    $('googleLogin').disabled = false;
    $('loginMsg').textContent = 'Não foi possível entrar. Tente de novo.';
  }
};
$('signOutBtn').onclick = () => { if (confirm('Sair da conta neste aparelho?')) signOutApp(); };

// Senha do casal (criar / desbloquear)
$('vaultForm').addEventListener('submit', async e => {
  e.preventDefault();
  const password = $('vaultPassword').value;
  const status = $('vaultStatus');
  status.textContent = '';
  if (vaultMode === 'unlock') {
    const wait = Math.ceil((lockedUntil - Date.now()) / 1000);
    if (wait > 0) { status.textContent = `Muitas tentativas. Aguarde ${wait} s.`; return; }
  }
  if (vaultMode === 'setup') {
    if (password.length < MIN_PW) { status.textContent = `A senha precisa ter pelo menos ${MIN_PW} caracteres.`; return; }
    if (password !== $('vaultConfirm').value) { status.textContent = 'As senhas não conferem.'; return; }
  }
  const submit = $('vaultSubmit');
  submit.disabled = true;
  status.textContent = vaultMode === 'setup' ? 'Criando… isso leva alguns segundos.' : 'Verificando…';
  try {
    if (vaultMode === 'setup') {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(password, salt);
      const ver = await encWith(key, { check: 'ok' }, 'mf3|verifier');
      const created = await B.store.createDocIfMissing('verifier', { s: b64(salt), ...ver });
      if (!created) {
        // alguém criou o casal antes: usa a senha dele
        status.textContent = 'O casal já tem senha criada. Digite a senha combinada.';
        vaultMode = 'unlock';
        const ver2 = await B.store.getDoc('verifier');
        coupleSalt = unb64(ver2.s);
        $('vaultConfirmWrap').hidden = true; $('strengthWrap').hidden = true;
        $('vaultTitle').textContent = 'Senha do casal';
        return;
      }
      coupleSalt = salt;
      cryptoKey = key;
      await KeyStore.put(key);
      failedTries = 0;
      return openApp();
    }
    const ver = await B.store.getDoc('verifier');
    if (!ver) throw new Error('Casal ainda não criado.');
    const salt = unb64(ver.s);
    const key = await deriveKey(password, salt);
    if (!(await checkKey(key, ver))) {
      const err = new Error('wrong');
      err.name = 'OperationError';
      throw err;
    }
    coupleSalt = salt;
    cryptoKey = key;
    await KeyStore.put(key);
    failedTries = 0;
    openApp();
  } catch (err) {
    if (err && err.name === 'OperationError') {
      failedTries++;
      if (failedTries >= 5) lockedUntil = Date.now() + Math.min(15 * 60e3, 30e3 * 2 ** (failedTries - 5));
      status.textContent = 'Senha incorreta.';
    } else {
      console.error(err);
      status.textContent = (err && err.message) || 'Não foi possível concluir.';
    }
  } finally {
    submit.disabled = false;
  }
});

// ---------- Utilitários de interface ----------
let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}

function showView(name) {
  view = name;
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.bn').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(s => s.classList.toggle('active', s.id === 'view-' + name));
  window.scrollTo(0, 0);
  renderAll();
}
document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));

function renderAll() {
  if (document.body.dataset.gate !== 'app') return;
  populateSelects();
  renderHome();
  renderTransactions();
  renderBudgets();
  renderCouple();
  applyWidths();
}
function applyWidths(root = document) {
  root.querySelectorAll('[data-w]').forEach(el => { el.style.width = el.dataset.w + '%'; });
}

// ---------- Boot ----------
function boot() {
  if (!cryptoReady()) {
    setGate('login');
    $('loginMsg').textContent = 'Este navegador não suporta a criptografia necessária. Use Chrome, Edge, Safari ou Firefox atualizados.';
    $('googleLogin').disabled = true;
    return;
  }
  if (!B) { showLogin('Configuração ausente.'); return; }
  setGate('login');
  B.onAuth(async user => {
    if (!user) {
      stopListening();
      cryptoKey = null;
      me = null;
      showLogin();
      return;
    }
    if (!user.emailVerified) { await B.signOut(); return showLogin('Use uma conta Google com e-mail verificado.'); }
    if (!MEMBERS[user.email]) {
      await B.signOut();
      return showLogin('Esta conta não faz parte deste casal. Entre com a conta autorizada.');
    }
    try {
      await startSession(user);
    } catch (err) {
      console.error(err);
      if (err && err.code === 'permission-denied') {
        await B.signOut();
        return showLogin('Esta conta não tem acesso a este casal.');
      }
      showLogin('Não foi possível conectar. Verifique a internet e tente de novo.');
    }
  });
}

const stamp = t => t.updatedAt || t.createdAt || '';

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}


// ---------- Filtros e seleções ----------
function populateSelects() {
  const pf = $('personFilter').value;
  $('personFilter').innerHTML = '<option value="">Todas as pessoas</option>' + people.map(p => `<option>${esc(p)}</option>`).join('');
  $('personFilter').value = people.includes(pf) ? pf : '';
  const cf = $('categoryFilter').value;
  const allCats = [...new Set([...CATS.expense, ...CATS.income])];
  $('categoryFilter').innerHTML = '<option value="">Todas as categorias</option>' + allCats.map(c => `<option>${esc(c)}</option>`).join('');
  $('categoryFilter').value = allCats.includes(cf) ? cf : '';
}
function fillPersonSelect(selected) {
  $('person').innerHTML = people.map(p => `<option>${esc(p)}</option>`).join('');
  $('person').value = people.includes(selected) ? selected : people[0];
}
function fillCategorySelect(kind, selected) {
  $('category').innerHTML = CATS[kind].map(c => `<option>${esc(c)}</option>`).join('');
  if (selected && CATS[kind].includes(selected)) $('category').value = selected;
}
function setKind(kind) {
  txKind = kind;
  document.querySelectorAll('#kindSeg button').forEach(b => b.classList.toggle('on', b.dataset.kind === kind));
  fillCategorySelect(kind);
}
document.querySelectorAll('#kindSeg button').forEach(b => b.addEventListener('click', () => setKind(b.dataset.kind)));

// ---------- Período ----------
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
function currentRange() {
  const anchor = new Date(periodAnchor.getFullYear(), periodAnchor.getMonth(), periodAnchor.getDate());
  let start = null, end = null, label = 'Todo o histórico';
  if (selectedPeriod === 'day') { start = anchor; end = new Date(anchor); end.setDate(end.getDate() + 1); label = anchor.toLocaleDateString('pt-BR', { weekday: 'long', day: 'numeric', month: 'long' }); }
  else if (selectedPeriod === 'week') { start = startOfWeek(anchor); end = new Date(start); end.setDate(end.getDate() + 7); label = `${start.toLocaleDateString('pt-BR', { day: 'numeric', month: 'short' })} – ${new Date(end - 1).toLocaleDateString('pt-BR', { day: 'numeric', month: 'short' })}`; }
  else if (selectedPeriod === 'month') { start = new Date(anchor.getFullYear(), anchor.getMonth(), 1); end = new Date(anchor.getFullYear(), anchor.getMonth() + 1, 1); label = anchor.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }); }
  else if (selectedPeriod === 'year') { start = new Date(anchor.getFullYear(), 0, 1); end = new Date(anchor.getFullYear() + 1, 0, 1); label = String(anchor.getFullYear()); }
  return { start, end, anchor, label: cap(label) };
}
function inRange(t, r) {
  if (!r.start) return true;
  const d = new Date(t.date + 'T12:00:00');
  return d >= r.start && d < r.end;
}
function movePeriod(step) {
  if (selectedPeriod === 'all') return;
  const d = new Date(periodAnchor);
  if (selectedPeriod === 'day') d.setDate(d.getDate() + step);
  else if (selectedPeriod === 'week') d.setDate(d.getDate() + 7 * step);
  else if (selectedPeriod === 'month') d.setMonth(d.getMonth() + step);
  else if (selectedPeriod === 'year') d.setFullYear(d.getFullYear() + step);
  periodAnchor = d;
  renderAll();
}
document.querySelectorAll('#periodSwitch button').forEach(b => b.addEventListener('click', () => {
  selectedPeriod = b.dataset.period;
  periodAnchor = new Date();
  document.querySelectorAll('#periodSwitch button').forEach(x => x.classList.toggle('on', x === b));
  renderAll();
}));
$('prevPeriod').onclick = () => movePeriod(-1);
$('nextPeriod').onclick = () => movePeriod(1);

function sortedTxs() {
  return [...txs].sort((a, b) => b.date.localeCompare(a.date) || stamp(b).localeCompare(stamp(a)));
}
function sumBy(list, key) {
  const out = {};
  list.forEach(t => { out[t[key]] = (out[t[key]] || 0) + t.amount; });
  return out;
}

// ---------- Início ----------
function renderHome() {
  const r = currentRange();
  $('periodCaption').textContent = r.label;
  const data = txs.filter(t => inRange(t, r));
  const expenses = data.filter(t => t.kind === 'expense');
  const out = sum(expenses), inc = sum(data.filter(t => t.kind === 'income'));
  $('spentTotal').textContent = money(out);
  $('incomeTotal').textContent = money(inc);
  $('balanceTotal').textContent = money(inc - out);
  $('balanceTotal').className = inc - out < 0 ? 'bad' : 'ok';
  $('countTotal').textContent = data.length;
  renderChart(expenses, r);

  const cats = Object.entries(sumBy(expenses, 'category')).sort((a, b) => b[1] - a[1]);
  $('categoryBars').innerHTML = cats.length
    ? cats.map(([c, v]) => `<div class="cat-row"><span>${CAT_ICON[c] || '•'} ${esc(c)}</span><b>${money(v)}</b><div class="progress"><span data-w="${(v / out * 100).toFixed(1)}"></span></div></div>`).join('')
    : '<p class="muted small">Sem despesas neste período.</p>';

  const byPerson = Object.entries(sumBy(expenses, 'person')).sort((a, b) => b[1] - a[1]);
  $('personSplit').innerHTML = byPerson.length
    ? byPerson.map(([p, v]) => `<div class="person-row"><div class="who"><span class="avatar">${esc(initials(p))}</span><div><b>${esc(p)}</b><small>${Math.round(v / out * 100)}% dos gastos</small></div></div><b>${money(v)}</b></div>`).join('')
    : '<p class="muted small">Sem despesas neste período.</p>';

  $('recentList').innerHTML = sortedTxs().filter(t => inRange(t, r)).slice(0, 5).map(txCard).join('')
    || '<div class="empty">Nenhum lançamento neste período.</div>';
}

function renderChart(expenses, r) {
  const chart = $('dailyChart');
  chart.innerHTML = '';
  let daily = [], labels = [];
  if (!r.start) { chart.innerHTML = '<p class="chart-empty">Escolha um período para ver o gráfico.</p>'; $('chartFirst').textContent = ''; $('chartLast').textContent = ''; $('chartMax').textContent = ''; return; }
  if (selectedPeriod === 'day') { daily = [sum(expenses)]; labels = ['Dia']; }
  else if (selectedPeriod === 'week') { daily = Array(7).fill(0); labels = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']; expenses.forEach(t => { daily[(new Date(t.date + 'T12:00:00').getDay() + 6) % 7] += t.amount; }); }
  else if (selectedPeriod === 'year') { daily = Array(12).fill(0); labels = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez']; expenses.forEach(t => { daily[Number(t.date.slice(5, 7)) - 1] += t.amount; }); }
  else { const n = new Date(r.anchor.getFullYear(), r.anchor.getMonth() + 1, 0).getDate(); daily = Array(n).fill(0); labels = daily.map((_, i) => String(i + 1)); expenses.forEach(t => { daily[Number(t.date.slice(8, 10)) - 1] += t.amount; }); }
  if (!daily.some(v => v > 0)) { chart.innerHTML = '<p class="chart-empty">Sem despesas neste período.</p>'; $('chartFirst').textContent = ''; $('chartLast').textContent = ''; $('chartMax').textContent = ''; return; }
  const peak = Math.max(...daily);
  daily.forEach((v, i) => {
    const col = document.createElement('div');
    col.className = 'bar-col';
    col.title = `${labels[i]}: ${money(v)}`;
    const bar = document.createElement('div');
    bar.className = 'bar' + (v ? '' : ' empty');
    bar.style.height = v ? Math.max(4, v / peak * 100) + '%' : '3px';
    col.appendChild(bar);
    chart.appendChild(col);
  });
  $('chartFirst').textContent = labels[0];
  $('chartLast').textContent = labels.at(-1);
  $('chartMax').textContent = 'Maior: ' + money(peak);
}

function txCard(t) {
  const inc = t.kind === 'income';
  return `<button class="tx" type="button" data-edit="${esc(t.id)}">
    <span class="tx-ico${inc ? ' income' : ''}" aria-hidden="true">${CAT_ICON[t.category] || '•'}</span>
    <span class="tx-main"><b>${esc(t.description)}</b><small>${esc(t.category)} · ${esc(t.person)} · ${fmtDate(t.date)}</small></span>
    <span class="amount ${inc ? 'income' : 'expense'}">${inc ? '+' : '−'} ${money(t.amount)}</span>
  </button>`;
}

// ---------- Lançamentos ----------
let lastTxFilterKey = '';
function renderTransactions() {
  const q = cleanText($('search').value.trim());
  const type = $('typeFilter').value, person = $('personFilter').value, cat = $('categoryFilter').value;
  const key = [q, type, person, cat, txLimit].join('|');
  if (key !== lastTxFilterKey) { lastTxFilterKey = key; }
  const list = sortedTxs().filter(t =>
    (!type || t.kind === type) && (!person || t.person === person) && (!cat || t.category === cat) &&
    (!q || cleanText([t.description, t.category, t.merchant, t.person, t.reference, t.notes].join(' ')).includes(q)));
  const empty = $('txEmpty');
  empty.hidden = list.length > 0;
  empty.textContent = txs.length ? 'Nenhum lançamento com esses filtros.' : 'Ainda não há lançamentos. Toque em “+ Novo lançamento”.';
  let html = '', lastDay = '';
  for (const t of list.slice(0, txLimit)) {
    if (t.date !== lastDay) { html += `<div class="day-head">${esc(fmtDay(t.date))}</div>`; lastDay = t.date; }
    html += txCard(t);
  }
  if (list.length > txLimit) html += `<button class="btn btn-ghost block mt" type="button" id="moreTx">Mostrar mais (${list.length - txLimit})</button>`;
  $('txList').innerHTML = html;
}
['search'].forEach(id => $(id).addEventListener('input', () => { txLimit = 200; renderTransactions(); }));
['typeFilter', 'personFilter', 'categoryFilter'].forEach(id => $(id).addEventListener('change', () => { txLimit = 200; renderTransactions(); }));
$('txList').addEventListener('click', e => {
  if (e.target.closest('#moreTx')) { txLimit += 200; return renderTransactions(); }
  const b = e.target.closest('[data-edit]');
  if (b) openTx(b.dataset.edit);
});
$('recentList').addEventListener('click', e => { const b = e.target.closest('[data-edit]'); if (b) openTx(b.dataset.edit); });

// Exportar planilha (CSV). Campos começando com = + - @ são neutralizados para evitar fórmulas maliciosas no Excel.
function csvCell(v) {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
$('csvBtn').onclick = () => {
  if (!cryptoKey) return;
  if (!confirm('A planilha será salva SEM criptografia. Guarde o arquivo em local seguro. Continuar?')) return;
  const head = ['Data', 'Tipo', 'Descrição', 'Categoria', 'Pessoa', 'Valor', 'Forma de pagamento', 'Estabelecimento', 'Observações'];
  const rows = sortedTxs().map(t => [t.date, t.kind === 'income' ? 'Receita' : 'Despesa', t.description, t.category, t.person, Number(t.amount).toFixed(2).replace('.', ','), t.payment, t.merchant, t.notes].map(csvCell).join(';'));
  downloadBlob(new Blob(['﻿' + [head.map(csvCell).join(';'), ...rows].join('\r\n')], { type: 'text/csv;charset=utf-8' }), `meu-financeiro-${today()}.csv`);
};

// ---------- Lançamento (criar / editar) ----------
function openTx(id = null) {
  if (!cryptoKey) return;
  const t = id ? txs.find(x => x.id === id) : null;
  editingId = t ? t.id : null;
  $('txForm').reset();
  $('txTitle').textContent = t ? 'Editar lançamento' : 'Novo lançamento';
  $('saveTx').textContent = t ? 'Salvar alterações' : 'Salvar';
  $('deleteTx').hidden = !t;
  setKind(t ? t.kind : 'expense');
  fillPersonSelect(t ? t.person : (me ? me.name : people[0]));
  if (t) {
    $('amountInput').value = digitsToBRL(Math.round(t.amount * 100));
    $('dateInput').value = t.date;
    $('description').value = t.description;
    fillCategorySelect(t.kind, t.category);
    $('payment').value = t.payment || 'Pix';
    $('merchant').value = t.merchant || '';
    $('documentType').value = t.documentType || '';
    $('beneficiary').value = t.beneficiary || '';
    $('payer').value = t.payer || '';
    $('dueDate').value = t.dueDate || '';
    $('reference').value = t.reference || '';
    $('documentNumber').value = t.documentNumber || '';
    $('notes').value = t.notes || '';
    document.querySelector('details.more').open = !!(t.beneficiary || t.payer || t.dueDate || t.reference || t.documentNumber || t.documentType || t.notes);
  } else {
    $('dateInput').value = today();
    document.querySelector('details.more').open = false;
  }
  receiptData = t && t.receipt ? t.receipt : '';
  selectedReceiptFile = null;
  if (receiptData) { $('scanPreview').src = receiptData; $('scanPreview').hidden = false; }
  else { $('scanPreview').removeAttribute('src'); $('scanPreview').hidden = true; }
  if (t && t.hasReceipt && !t.receipt) {
    fetchReceipt(t.id).then(r => {
      if (!r || editingId !== t.id) return;
      receiptData = r; $('scanPreview').src = r; $('scanPreview').hidden = false;
    }).catch(err => console.error(err));
  }
  $('ocrBtn').disabled = true;
  $('ocrStatus').textContent = '';
  $('txModal').classList.add('show');
  if (!t) setTimeout(() => $('amountInput').focus(), 80);
}
function closeTx() {
  $('txModal').classList.remove('show');
  editingId = null; receiptData = ''; selectedReceiptFile = null;
}
$('newBtn').onclick = () => openTx();
$('mobileAdd').onclick = () => openTx();
$('closeModal').onclick = closeTx;
$('cancelModal').onclick = closeTx;

$('txForm').addEventListener('submit', async e => {
  e.preventDefault();
  const amount = parseBRL($('amountInput').value);
  if (!(amount > 0)) { $('amountInput').focus(); return toast('Informe um valor maior que zero.'); }
  const data = {
    kind: txKind, amount,
    description: $('description').value.trim(), category: $('category').value, person: $('person').value,
    date: $('dateInput').value || today(), payment: $('payment').value, notes: $('notes').value.trim(),
    merchant: $('merchant').value.trim(), beneficiary: $('beneficiary').value.trim(), payer: $('payer').value.trim(),
    dueDate: $('dueDate').value, reference: $('reference').value.trim(), documentNumber: $('documentNumber').value.trim(),
    documentType: $('documentType').value.trim()
  };
  if (!data.description) { $('description').focus(); return toast('Informe a descrição.'); }
  const wasEdit = !!editingId, id = editingId, now = nowISO();
  const ok = await commitChange(() => {
    if (wasEdit) {
      const i = txs.findIndex(t => t.id === id);
      if (i < 0) return;
      const next = { ...txs[i], ...data, updatedAt: now };
      if (receiptData) next.receipt = receiptData;
      txs = txs.map((t, j) => (j === i ? next : t));
    } else {
      const tx = { id: newId(), ...data, createdAt: now, updatedAt: now };
      if (receiptData) tx.receipt = receiptData;
      txs = [tx, ...txs];
    }
  });
  if (ok) { closeTx(); toast(wasEdit ? 'Lançamento atualizado.' : 'Lançamento salvo.'); }
});

$('deleteTx').onclick = async () => {
  if (!editingId) return;
  if (!confirm('Excluir este lançamento? A exclusão vale nos dois aparelhos.')) return;
  const id = editingId;
  const ok = await commitChange(() => {
    txs = txs.filter(t => t.id !== id);
  });
  if (ok) { closeTx(); toast('Lançamento excluído.'); }
};

// ---------- Receitas: comprovante ----------
function compressReceipt(file) {
  return createImageBitmap(file).then(bitmap => {
    const max = 1600;
    const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close?.();
    return canvas.toDataURL('image/jpeg', 0.8);
  });
}
$('cameraPick').onclick = () => $('cameraFile').click();
$('galleryPick').onclick = () => $('receiptFile').click();
async function attachReceipt(file) {
  if (!file) return;
  if (!file.type.startsWith('image/')) return toast('Escolha uma imagem (foto).');
  selectedReceiptFile = file;
  $('ocrStatus').textContent = 'Preparando foto…';
  try {
    receiptData = await compressReceipt(file);
    $('scanPreview').src = receiptData;
    $('scanPreview').hidden = false;
    $('ocrBtn').disabled = false;
    $('ocrStatus').textContent = 'Foto anexada. Preencha os campos ou toque em “Ler com OCR”.';
  } catch (err) {
    console.error(err);
    receiptData = ''; selectedReceiptFile = null;
    $('ocrBtn').disabled = true;
    $('ocrStatus').textContent = 'Não foi possível processar esta imagem. Tente outra foto.';
  }
}
$('receiptFile').onchange = e => attachReceipt(e.target.files[0]);
$('cameraFile').onchange = e => attachReceipt(e.target.files[0]);

// ---------- Voz ----------
$('voiceAdd').onclick = () => {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) return toast('Reconhecimento de voz indisponível neste navegador. Use o lançamento manual.');
  if (!confirm('O reconhecimento de voz pode enviar o áudio ao serviço de fala do navegador. Continuar?')) return;
  const rec = new SR();
  rec.lang = 'pt-BR';
  rec.interimResults = false;
  rec.maxAlternatives = 1;
  rec.onresult = e => {
    const said = e.results[0][0].transcript.trim();
    const m = said.match(/(\d+(?:[.,]\d{1,2})?)\s*(?:reais|real|r\$)/i);
    openTx();
    if (m) $('amountInput').value = digitsToBRL(String(Math.round(Number(m[1].replace(',', '.')) * 100)));
    $('description').value = ((m ? said.replace(m[0], '') : said).replace(/\s+/g, ' ').trim() || said).slice(0, 300);
  };
  rec.onerror = () => toast('Não foi possível reconhecer a fala. Tente de novo.');
  rec.start();
};

// ---------- OCR (opcional; o usuário pode sempre preencher à mão) ----------
const TESS_BASE = 'https://cdn.jsdelivr.net/npm';
let ocrWorkerPromise = null;
function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error('Não foi possível carregar a biblioteca de leitura. Confira a conexão com a internet.'));
    document.head.appendChild(s);
  });
}
async function getOCRWorker(onStatus) {
  if (!window.Tesseract) await loadScript(`${TESS_BASE}/tesseract.js@5.1.1/dist/tesseract.min.js`);
  if (!ocrWorkerPromise) {
    ocrWorkerPromise = Tesseract.createWorker('por', 1, {
      workerPath: `${TESS_BASE}/tesseract.js@5.1.1/dist/worker.min.js`,
      corePath: `${TESS_BASE}/tesseract.js-core@5.1.1/tesseract-core.wasm.js`,
      langPath: `${TESS_BASE}/@tesseract.js-data/por/4.0.0_best_int`,
      workerBlobURL: true,
      logger: m => { if (m.status) onStatus(m.status + (m.progress ? ' · ' + Math.round(m.progress * 100) + '%' : '')); }
    }).catch(err => { ocrWorkerPromise = null; throw err; });
  }
  return ocrWorkerPromise;
}
async function prepareReceiptImage(file) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1.4, 2200 / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale)), h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0, w, h);
  const frame = ctx.getImageData(0, 0, w, h), px = frame.data;
  for (let i = 0; i < px.length; i += 4) {
    const gray = .299 * px[i] + .587 * px[i + 1] + .114 * px[i + 2];
    const v = Math.max(0, Math.min(255, (gray - 105) * 1.55 + 128));
    px[i] = px[i + 1] = px[i + 2] = v;
  }
  ctx.putImageData(frame, 0, 0);
  return canvas;
}
function cropPayerArea(source) {
  const c = document.createElement('canvas');
  const y = Math.round(source.height * .49), h = Math.round(source.height * .24);
  c.width = source.width; c.height = h;
  c.getContext('2d').drawImage(source, 0, y, source.width, h, 0, 0, c.width, c.height);
  return c;
}
function norm(s) { return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\s+/g, ' ').trim(); }
function toMoney(s) {
  let v = String(s || '').replace(/[^\d,.]/g, '');
  if (v.includes(',')) v = v.replace(/\./g, '').replace(',', '.');
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n < 1000000 ? n : null;
}
function toISO(s) {
  const m = String(s || '').match(/\b(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})\b/);
  if (!m) return '';
  let y = +m[3]; if (y < 100) y += 2000;
  const d = +m[1], mo = +m[2];
  return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 ? `${y}-${pad(mo)}-${pad(d)}` : '';
}
// Tenta achar um nome de pessoa/empresa em um trecho de texto (melhor esforço; o campo é editável).
function guessName(text) {
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw
      .replace(/pagador/ig, ' ')
      .replace(/\b(CPF|CNPJ)\b.*$/i, '')
      .split(/\b(?:RUA|AV\.?|AVENIDA|R\.|ALAMEDA|VIELA|CEP|BAIRRO)\b/i)[0]
      .replace(/[^A-Za-zÀ-ÿ\s'.-]/g, ' ').replace(/\s+/g, ' ').trim();
    if (line.length >= 8 && line.split(' ').length >= 2) return line;
  }
  return '';
}

function parseDocument(text) {
  const lines = String(text || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const ns = lines.map(norm), all = norm(text);
  const f = { amount: null, confidence: 'none', issueDate: '', dueDate: '', merchant: '', beneficiary: '', payer: '', reference: '', documentNumber: '', category: 'Outros', description: 'Documento / pagamento', payment: '', type: 'Documento' };

  const rules = [
    { re: /escola|colegio|educacao|mensalidade|aluno|ensino|educacional|material didatico/i, type: 'Cobrança escolar', category: 'Educação', description: 'Mensalidade escolar', payment: 'Boleto' },
    { re: /posto|combustivel|gasolina|etanol|diesel|abastecimento/i, type: 'Comprovante de combustível', category: 'Combustível', description: 'Abastecimento', payment: '' },
    { re: /supermercado|mercado|acougue|padaria|restaurante|lanchonete/i, type: 'Cupom / nota de compra', category: 'Alimentação', description: 'Compra de alimentação', payment: 'Cartão de débito' },
    { re: /farmacia|drogaria/i, type: 'Comprovante de farmácia', category: 'Saúde', description: 'Compra em farmácia', payment: '' },
    { re: /energia|equatorial|saneago|agua|internet|telefonia/i, type: 'Conta de consumo', category: 'Contas domésticas', description: 'Pagamento de conta', payment: 'Boleto' },
    { re: /boleto|linha digitavel|beneficiario|pagador|nosso numero|valor do documento/i, type: 'Boleto bancário', category: 'Outros', description: 'Pagamento de boleto', payment: 'Boleto' }
  ];
  const rule = rules.find(r => r.re.test(all));
  if (rule) { f.type = rule.type; f.category = rule.category; f.description = rule.description; f.payment = rule.payment; }

  // Valor só é considerado confiável quando aparece junto a um rótulo financeiro explícito.
  for (let i = 0; i < lines.length; i++) {
    if (/valor do documento|valor a pagar|valor cobrado|total a pagar|valor total|total do documento|valor com desconto/i.test(ns[i])) {
      for (const line of [lines[i], lines[i + 1] || '', lines[i + 2] || '']) {
        const m = line.match(/(?:R\$\s*)?(\d{1,3}(?:\.\d{3})*,\d{2}|\d+,\d{2})/i);
        if (m) { const v = toMoney(m[1]); if (v !== null) { f.amount = v; f.confidence = 'high'; break; } }
      }
      if (f.amount !== null) break;
    }
  }
  if (f.amount === null) {
    const vals = [];
    for (const line of lines) {
      if (/linha digitavel|codigo de barras|nosso numero|cpf|cnpj/i.test(norm(line))) continue;
      for (const m of line.matchAll(/R\$\s*(\d{1,3}(?:\.\d{3})*,\d{2}|\d+,\d{2})/gi)) { const v = toMoney(m[1]); if (v !== null) vals.push(v); }
    }
    const unique = [...new Set(vals)];
    if (unique.length === 1) { f.amount = unique[0]; f.confidence = 'medium'; }
  }

  function field(labels) {
    for (let i = 0; i < ns.length; i++) {
      if (labels.some(r => r.test(ns[i]))) {
        let v = lines[i].replace(/^[^:]{0,60}[:\-]?\s*/, '').trim();
        if (!v || labels.some(r => r.test(norm(v)))) v = (lines[i + 1] || '').trim();
        v = v.replace(/^\d+\s*/, '').trim();
        if (v.length > 2 && v.length < 110 && !/\d{8,}/.test(v)) return v;
      }
    }
    return '';
  }
  f.beneficiary = field([/^beneficiario\b/i, /nome do beneficiario/i, /cedente\b/i]);
  f.payer = field([/^pagador\b/i, /nome do pagador/i, /sacado\b/i]);
  // Em boletos, o OCR pode juntar o nome do pagador com o endereço da linha seguinte.
  const payerLine = lines.find(x => /pagador/i.test(x));
  if (payerLine) {
    const candidate = payerLine.replace(/^.*?pagador\s*/i, '').split(/\b(?:VIELA|RUA|AVENIDA|AV\.?|R\.|ALAMEDA|CEP)\b/i)[0].replace(/[|,;:]+$/, '').trim();
    if (candidate.length > 8) f.payer = candidate;
  }
  f.payer = f.payer.replace(/\s+(?:CPF|CNPJ).*$/i, '').trim();
  f.beneficiary = f.beneficiary.replace(/\s+(?:CPF|CNPJ).*$/i, '').trim();
  f.merchant = f.beneficiary || field([/^estabelecimento\b/i, /^empresa\b/i, /razao social/i, /nome fantasia/i]);
  f.reference = field([/referencia\b/i, /competencia\b/i, /mensalidade\b/i, /referente a/i]);

  // Número do documento: após "Número do Documento" ou "Nosso número"; não confundir com "Valor do documento".
  for (let i = 0; i < ns.length; i++) {
    if (/(?:numero|n[ºo°])\s+do\s+documento|nosso\s+numero/i.test(ns[i]) && !/valor\s+do\s+documento/i.test(ns[i])) {
      // Usa o texto normalizado (sem acentos), senão "Número do Documento" não casa com a regex.
      const labelMatch = ns[i].match(/(?:numero|n[ºo°])\s+do\s+documento|nosso\s+numero/i);
      const tail = labelMatch ? ns[i].slice(labelMatch.index + labelMatch[0].length) : '';
      for (const candidate of [tail, lines[i + 1] || '']) {
        const m = candidate.match(/\b(\d{4,20})\b/);
        if (m && !/^0+$/.test(m[1])) { f.documentNumber = m[1]; break; }
      }
      if (f.documentNumber) break;
    }
  }
  for (let i = 0; i < ns.length; i++) {
    if (/vencimento|data de vencimento/i.test(ns[i])) { f.dueDate = toISO(lines[i]) || toISO(lines[i + 1] || ''); if (f.dueDate) break; }
  }
  for (let i = 0; i < ns.length; i++) {
    if (/data do documento|data de emissao|emitido em/i.test(ns[i])) { f.issueDate = toISO(lines[i]) || toISO(lines[i + 1] || ''); if (f.issueDate) break; }
  }
  if (f.type === 'Cobrança escolar' && f.beneficiary) f.description = 'Mensalidade escolar - ' + f.beneficiary.slice(0, 55);
  return f;
}

function applyOCR(d, ocrConfidence) {
  setKind('expense');
  $('category').value = d.category;
  $('description').value = d.description;
  if (d.amount !== null) $('amountInput').value = digitsToBRL(String(Math.round(d.amount * 100)));
  if (d.payment) $('payment').value = d.payment;
  if (d.type) $('documentType').value = d.type;
  for (const [id, key] of [['merchant', 'merchant'], ['beneficiary', 'beneficiary'], ['payer', 'payer'], ['dueDate', 'dueDate'], ['reference', 'reference'], ['documentNumber', 'documentNumber']]) {
    if (d[key]) $(id).value = d[key];
  }
  if (d.issueDate) $('dateInput').value = d.issueDate;
  const extra = [d.type, d.reference ? 'Referência: ' + d.reference : '', d.documentNumber ? 'Documento: ' + d.documentNumber : ''].filter(Boolean);
  if (extra.length && !$('notes').value.trim()) $('notes').value = extra.join('\n');
  const filled = [d.merchant, d.beneficiary, d.payer, d.dueDate, d.reference, d.documentNumber].filter(Boolean).length;
  let msg = (d.confidence === 'high' ? 'Valor identificado junto ao campo do documento'
    : d.confidence === 'medium' ? 'Valor provável identificado' : 'Valor não identificado com segurança')
    + (d.amount !== null ? ': ' + money(d.amount) : '') + `. ${filled} campo(s) adicional(is) preenchido(s). Revise antes de salvar.`;
  if (ocrConfidence < 55) msg += ' A foto parece pouco nítida; tente fotografar de frente, sem movimento e com boa iluminação.';
  $('ocrStatus').textContent = msg;
}

async function readReceipt() {
  if (!selectedReceiptFile) return alert('Primeiro tire uma foto ou escolha uma imagem da galeria.');
  const btn = $('ocrBtn'), status = $('ocrStatus');
  btn.disabled = true;
  status.textContent = 'Preparando documento…';
  try {
    const image = await prepareReceiptImage(selectedReceiptFile);
    const worker = await getOCRWorker(msg => { status.textContent = msg; });
    status.textContent = 'Lendo documento em português…';
    await worker.setParameters({ tessedit_pageseg_mode: '3' });
    const result = await worker.recognize(image);
    const d = parseDocument(result.data.text || '');
    if (!d.payer) {
      status.textContent = 'Relendo a área do pagador…';
      await worker.setParameters({ tessedit_pageseg_mode: '11' });
      try {
        const extra = await worker.recognize(cropPayerArea(image));
        const guess = guessName(extra.data.text || '');
        if (guess) d.payer = guess;
      } finally {
        await worker.setParameters({ tessedit_pageseg_mode: '3' });
      }
    }
    applyOCR(d, result.data.confidence);
  } catch (err) {
    console.error(err);
    status.textContent = 'O reconhecimento não foi concluído: ' + (err && err.message ? err.message : 'erro desconhecido') + '. A foto continua anexada; preencha os campos manualmente e salve normalmente.';
  } finally {
    btn.disabled = false;
  }
}
$('ocrBtn').onclick = readReceipt;


// ---------- Orçamentos ----------
function renderBudgets() {
  const now = new Date();
  $('budgetMonth').textContent = cap(now.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }));
  const mk = monthKey(now);
  const exp = txs.filter(t => t.kind === 'expense' && t.date.startsWith(mk));
  const spentBy = sumBy(exp, 'category');
  const spentAll = sum(exp);
  const limited = Object.keys(budgets);
  const limitTotal = limited.reduce((a, c) => a + budgets[c], 0);
  const spentLimited = limited.reduce((a, c) => a + (spentBy[c] || 0), 0);
  $('budgetSpent').textContent = money(spentAll);
  $('budgetLimit').textContent = limitTotal ? money(limitTotal) : '—';
  $('budgetLeft').textContent = limitTotal ? money(limitTotal - spentLimited) : '—';
  $('budgetLeft').className = limitTotal && limitTotal - spentLimited < 0 ? 'bad' : '';
  const pct = limitTotal ? Math.min(100, spentLimited / limitTotal * 100) : 0;
  $('budgetAll').dataset.w = pct.toFixed(1);
  $('budgetAll').className = limitTotal && spentLimited > limitTotal ? 'over' : '';
  $('budgetHint').textContent = limitTotal
    ? `Nas categorias com limite, vocês já usaram ${Math.round(spentLimited / limitTotal * 100)}% do total.`
    : 'Defina limites abaixo para acompanhar o mês.';
  $('budgetList').innerHTML = CATS.expense.map(c => {
    const limit = budgets[c] || 0, spent = spentBy[c] || 0;
    const p = limit ? Math.min(100, spent / limit * 100) : 0;
    const over = limit && spent > limit;
    return `<div class="bar-row">
      <span class="name">${CAT_ICON[c] || '•'} ${esc(c)}</span>
      <span class="val ${over ? 'bad' : ''}">${money(spent)}${limit ? ' de ' + money(limit) : ''}</span>
      <div class="progress"><span class="${over ? 'over' : ''}" data-w="${p.toFixed(1)}"></span></div>
      <div class="budget-input"><input inputmode="numeric" data-budget="${esc(c)}" value="${limit ? digitsToBRL(Math.round(limit * 100)) : ''}" placeholder="Sem limite" aria-label="Limite mensal de ${esc(c)}"></div>
    </div>`;
  }).join('');
}
$('budgetList').addEventListener('input', e => {
  const el = e.target;
  if (!el.matches('[data-budget]')) return;
  const digits = el.value.replace(/\D/g, '').slice(0, 12);
  el.value = digits ? digitsToBRL(digits) : '';
});
$('budgetList').addEventListener('change', async e => {
  const el = e.target;
  if (!el.matches('[data-budget]')) return;
  const cat = el.dataset.budget, value = parseBRL(el.value);
  const next = { ...budgets };
  if (value > 0) next[cat] = value; else delete next[cat];
  await commitChange(() => { budgets = next; budgetsAt = nowISO(); });
});

// ---------- Casal ----------
function renderCouple() {
  const memberNames = Object.values(MEMBERS);
  $('peopleList').innerHTML = people.map(p => {
    const n = txs.filter(t => t.person === p).length;
    const isMember = memberNames.includes(p);
    const actions = isMember
      ? '<span class="muted small">Integrante do casal</span>'
      : `<button class="btn btn-ghost" type="button" data-rename="${esc(p)}">Renomear</button><button class="btn btn-danger" type="button" data-remove="${esc(p)}">Remover</button>`;
    return `<div class="person-row">
      <div class="who"><span class="avatar">${esc(initials(p))}</span><div><b>${esc(p)}</b><small>${n} lançamento(s)</small></div></div>
      <div class="actions">${actions}</div>
    </div>`;
  }).join('');
  $('whoami2').textContent = me ? me.name : '';
  $('syncInfo').textContent = 'Os lançamentos são sincronizados em tempo real entre os aparelhos. Sem internet, ficam salvos e são enviados ao reconectar.';
}

$('peopleList').addEventListener('click', async e => {
  const ren = e.target.closest('[data-rename]'), rem = e.target.closest('[data-remove]');
  if (ren) {
    $('personModalTitle').textContent = 'Renomear pessoa';
    $('personModalName').value = ren.dataset.rename;
    $('personModal').dataset.old = ren.dataset.rename;
    $('personModal').classList.add('show');
    setTimeout(() => $('personModalName').focus(), 50);
  }
  if (rem) {
    const p = rem.dataset.remove;
    if (Object.values(MEMBERS).includes(p)) return toast('Integrantes do casal não podem ser removidos.');
    if (txs.some(t => t.person === p)) return toast('Esta pessoa tem lançamentos. Reatribua ou exclua esses lançamentos antes de remover.');
    if (people.length <= 1) return toast('Mantenha pelo menos uma pessoa cadastrada.');
    if (!confirm(`Remover ${p}?`)) return;
    const ok = await commitChange(() => { people = people.filter(x => x !== p); });
    if (ok) toast('Pessoa removida.');
  }
});
$('personForm').addEventListener('submit', async e => {
  e.preventDefault();
  const name = $('personName').value.trim().slice(0, 40);
  if (!name) return;
  if (people.some(x => x.toLowerCase() === name.toLowerCase())) return toast('Essa pessoa já está cadastrada.');
  const ok = await commitChange(() => { people = [...people, name]; });
  if (ok) { $('personName').value = ''; toast('Pessoa adicionada.'); }
});
$('cancelPerson').onclick = $('closePerson').onclick = () => $('personModal').classList.remove('show');
$('savePerson').onclick = async () => {
  const oldName = $('personModal').dataset.old;
  const name = $('personModalName').value.trim().slice(0, 40);
  if (!name || !oldName) return;
  if (name !== oldName && people.some(x => x.toLowerCase() === name.toLowerCase())) return toast('Já existe alguém com esse nome.');
  const now = nowISO();
  const ok = await commitChange(() => {
    people = people.map(p => (p === oldName ? name : p));
    txs = txs.map(t => (t.person === oldName ? { ...t, person: name, updatedAt: now } : t));
  });
  if (ok) { $('personModal').classList.remove('show'); toast('Nome atualizado.'); }
};


$('lockBtn').onclick = () => lockApp();
$('lockBtn2').onclick = () => lockApp();

$('changePassBtn').onclick = () => {
  $('passNew').value = ''; $('passConfirm').value = ''; $('passStatus').textContent = ''; $('passHint').textContent = '';
  $('passModal').classList.add('show');
  setTimeout(() => $('passNew').focus(), 50);
};
$('passNew').addEventListener('input', () => {
  const pw = $('passNew').value, s = strengthOf(pw);
  $('passHint').textContent = pw ? `Força: ${['Muito fraca', 'Fraca', 'Razoável', 'Boa', 'Forte'][s]}. Depois de trocar, o outro aparelho vai pedir a nova senha.` : 'Depois de trocar, o outro aparelho vai pedir a nova senha.';
});
$('closePass').onclick = $('cancelPass').onclick = () => $('passModal').classList.remove('show');
$('savePass').onclick = async () => {
  const a = $('passNew').value, b = $('passConfirm').value;
  if (a.length < MIN_PW) return ($('passStatus').textContent = `A senha precisa ter pelo menos ${MIN_PW} caracteres.`);
  if (a !== b) return ($('passStatus').textContent = 'As senhas não conferem.');
  $('savePass').disabled = true;
  try {
    await rotatePassphrase(a);
    $('passModal').classList.remove('show');
    toast('Senha do casal trocada. Use a nova senha no outro aparelho.');
  } catch (err) {
    console.error(err);
    $('passStatus').textContent = 'Não foi possível trocar a senha. Tente de novo.';
  } finally {
    $('savePass').disabled = false;
    $('passNew').value = ''; $('passConfirm').value = '';
  }
};

$('backupBtn').onclick = () => {
  if (!cryptoKey) return;
  if (!confirm('O backup será salvo SEM criptografia, com todos os seus dados. Guarde o arquivo em local seguro. Continuar?')) return;
  const snap = snapshot();
  const body = { backup: 'Meu Financeiro', format: 'meu-financeiro-backup', version: 3, createdAt: nowISO(), data: { people: snap.people, transactions: snap.transactions, budgets: snap.budgets, budgetsAt: snap.budgetsAt } };
  downloadBlob(new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }), `meu-financeiro-backup-${today()}.json`);
};
$('restoreBtn').onclick = () => $('restoreFile').click();
$('restoreFile').addEventListener('change', async e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (!f || !cryptoKey) return;
  try {
    if (f.size > 25 * 1024 * 1024) throw new Error('O arquivo excede 25 MB.');
    const d = JSON.parse(await f.text());
    const isBackup = d && d.data && (d.format === 'meu-financeiro-backup' || d.backup === 'Meu Financeiro' || d.backup === 'Meu Financeiro DEV');
    const clean = validateData(isBackup ? d.data : d);
    if (!confirm(`Importar o backup vai SUBSTITUIR os dados atuais deste celular (${txs.length} lançamento(s) hoje; ${clean.transactions.length} no backup). Continuar?`)) return;
    const ok = await commitChange(() => loadData(clean));
    if (ok) toast('Backup importado.');
  } catch (err) {
    alert('Não foi possível importar: ' + (err.message || 'arquivo inválido.'));
  }
});

// ---------- Eventos gerais ----------
document.querySelectorAll('.modal').forEach(m => m.addEventListener('click', e => {
  if (e.target !== m) return;
  if (m.id === 'txModal') closeTx();
  else m.classList.remove('show');
}));
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  closeTx();
  ['personModal', 'passModal'].forEach(id => $(id).classList.remove('show'));
});
$('txList').classList.add('list');
$('recentList').classList.add('list');
$('peopleList').classList.add('list');

boot();

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CardBoardMKT — Auth Demo</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  body{background:#111;color:#eee;font-family:Arial;margin:0;padding:20px}
  h1{color:#0f0;margin:0 0 8px}
  .panel{background:#0f0f0f;border:1px solid #222;border-radius:10px;padding:14px;margin-bottom:12px}
  .grid64{display:grid;grid-template-columns:repeat(8,28px);gap:6px;margin-top:8px}
  .grid64 button{width:28px;height:28px;background:#222;color:#9aa;border:1px solid #333;border-radius:4px;cursor:pointer}
  .grid64 button.active{background:#0f0;color:#000}
  .row{display:flex;gap:10px;align-items:center;margin:8px 0}
  input,button{padding:8px;border-radius:6px;border:1px solid #333;background:#0b0b0b;color:#eee}
  button.btn{background:#0f0;color:#000;border:1px solid #060}
  .muted{color:#9aa}
  .small{font-size:0.9em}
  .ok{color:#0f0}.err{color:#f55}
</style>
</head>
<body>

<h1>Authorization demo (AES-binding puzzle + nonce + audit)</h1>

<div class="panel">
  <div class="row">
    <label class="small muted">Email</label>
    <input id="email" type="email" placeholder="you@example.com" />
    <button id="btnGen" class="btn">Generate + Encrypt</button>
    <button id="btnDecrypt" class="btn">Decrypt (for download)</button>
  </div>

  <div class="small muted">Puzzle: select exactly <span id="nBitsLabel"></span> of 64 bits</div>
  <div class="small muted">Challenge: <span id="challengeHex">—</span></div>
  <div id="grid" class="grid64"></div>

  <div class="row">
    <span class="small muted">Status:</span>
    <span id="status" class="small">Ready</span>
  </div>
  <div class="row">
    <div class="small muted">Stored (encrypted) payload key: cbmkt_credentials_enc</div>
  </div>
</div>

<div class="panel">
  <div class="row">
    <button id="btnNonce" class="btn">Request nonce</button>
    <button id="btnActivate" class="btn">Activate (nonce + audit)</button>
    <button id="btnMigrate" class="btn">Migrate (nonce + OTP + audit)</button>
  </div>
  <div class="small muted">Diagnostic (masked):</div>
  <div class="small">
    Count: <span id="diagCount">—</span> |
    Created: <span id="diagCreated">—</span> |
    Checksum (prefix): <span id="diagChecksum">—</span>
  </div>
</div>

<script>
// --- Constants ---
const ENC_KEY = 'cbmkt_credentials_enc';
const PUZ_KEY = 'cbmkt_puzzle';
const N_BITS_DEFAULT = 16;

// --- Puzzle helpers ---
function getOrCreatePuzzle(nBits = N_BITS_DEFAULT) {
  const existing = JSON.parse(localStorage.getItem(PUZ_KEY) || 'null');
  if (existing) return existing;
  const u8 = new Uint8Array(8); crypto.getRandomValues(u8);
  const challengeHex = [...u8].map(b=>b.toString(16).padStart(2,'0')).join('');
  const puzzle = { challenge_hex: challengeHex.toUpperCase(), n_bits: nBits };
  localStorage.setItem(PUZ_KEY, JSON.stringify(puzzle));
  return puzzle;
}
function selectionToMaskHex(selectedIndexes) {
  let hi = 0n, lo = 0n;
  for (const idx of selectedIndexes) {
    if (idx < 32) lo |= (1n << BigInt(idx));
    else hi |= (1n << BigInt(idx - 32));
  }
  const loHex = lo.toString(16).padStart(8,'0');
  const hiHex = hi.toString(16).padStart(8,'0');
  return (hiHex + loHex).toUpperCase();
}

// --- KDF (PBKDF2-SHA256) ---
async function deriveAesKey(challengeHex, maskHex, saltB64) {
  const passphrase = challengeHex + ':' + maskHex;
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  const salt = Uint8Array.from(atob(saltB64), c=>c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey('raw', passBytes, { name:'PBKDF2' }, false, ['deriveBits','deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name:'PBKDF2', hash:'SHA-256', salt, iterations: 250000 },
    baseKey,
    { name:'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
  return aesKey;
}

// --- AES-GCM encrypt/decrypt ---
async function encryptCredentials(meta, selectedIndexes) {
  const puzzle = getOrCreatePuzzle();
  if (selectedIndexes.length !== puzzle.n_bits) throw new Error('Select exactly ' + puzzle.n_bits + ' bits.');
  const maskHex = selectionToMaskHex(selectedIndexes);
  const saltU8 = new Uint8Array(16); crypto.getRandomValues(saltU8);
  const saltB64 = btoa(String.fromCharCode(...saltU8));
  const key = await deriveAesKey(puzzle.challenge_hex, maskHex, saltB64);

  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const ivB64 = btoa(String.fromCharCode(...iv));
  const pt = new TextEncoder().encode(JSON.stringify(meta));
  const ctBuf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, pt);
  const ctU8 = new Uint8Array(ctBuf);
  const ctB64 = btoa(String.fromCharCode(...ctU8));
  const payload = {
    enc: { alg:'AES-GCM', kdf:'PBKDF2-SHA256', salt_b64:saltB64, iv_b64:ivB64, ct_b64:ctB64 },
    puzzle: { challenge_hex: puzzle.challenge_hex, n_bits: puzzle.n_bits },
    meta: { created_at: meta.created_at, email: meta.email }
  };
  localStorage.setItem(ENC_KEY, JSON.stringify(payload));
  return payload;
}
async function decryptCredentials(selectedIndexes) {
  const payload = JSON.parse(localStorage.getItem(ENC_KEY) || 'null');
  if (!payload) throw new Error('no_encrypted_credentials');
  const { challenge_hex, n_bits } = payload.puzzle;
  if (selectedIndexes.length !== n_bits) throw new Error('wrong_puzzle_bits');

  const maskHex = selectionToMaskHex(selectedIndexes);
  const key = await deriveAesKey(challenge_hex, maskHex, payload.enc.salt_b64);
  const iv = Uint8Array.from(atob(payload.enc.iv_b64), c=>c.charCodeAt(0));
  const ct = Uint8Array.from(atob(payload.enc.ct_b64), c=>c.charCodeAt(0));
  const ptBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  const pt = new TextDecoder().decode(ptBuf);
  return JSON.parse(pt);
}

// --- Original credential generation helpers (adapted) ---
const bufToHex = buf => [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
const rand5 = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5,'0');
async function computeChecksumHex(numbers){
  const enc = new TextEncoder();
  const json = JSON.stringify(numbers);
  const h = await crypto.subtle.digest('SHA-256', enc.encode(json));
  return bufToHex(h);
}
async function generatePlain(email){
  const numbers = []; for (let i=0;i<50;i++) numbers.push(rand5());
  const created_at = Math.floor(Date.now()/1000);
  const checksum = await computeChecksumHex(numbers);
  return { numbers, checksum, created_at, email };
}

// --- Small helpers ---
function selectedIndexesFromUI(n) {
  const sel = [];
  document.querySelectorAll('.grid64 button.active').forEach(b=>{
    sel.push(parseInt(b.dataset.idx,10));
  });
  if (sel.length !== n) throw new Error('Select exactly ' + n + ' bits.');
  return sel;
}
function maskDiag(meta){
  document.getElementById('diagCount').textContent = (meta?.numbers?.length ?? '—');
  document.getElementById('diagCreated').textContent = (meta?.created_at ?? '—');
  const pref = (meta?.checksum ? meta.checksum.slice(0,12)+'…' : '—');
  document.getElementById('diagChecksum').textContent = pref;
}
function setStatus(msg, cls=''){
  const el = document.getElementById('status'); el.textContent = msg; el.className = 'small ' + cls;
}

// --- UI init ---
const puzzle = getOrCreatePuzzle(N_BITS_DEFAULT);
document.getElementById('challengeHex').textContent = puzzle.challenge_hex;
document.getElementById('nBitsLabel').textContent = puzzle.n_bits;
const grid = document.getElementById('grid');
for (let i=0;i<64;i++){
  const b=document.createElement('button'); b.textContent=i+1; b.dataset.idx=i;
  b.addEventListener('click', ()=>{
    if (b.classList.contains('active')) { b.classList.remove('active'); }
    else {
      const n = document.querySelectorAll('.grid64 button.active').length;
      if (n >= puzzle.n_bits) return;
      b.classList.add('active');
    }
  });
  grid.appendChild(b);
}

// --- Buttons ---
document.getElementById('btnGen').addEventListener('click', async ()=>{
  try {
    setStatus('Generating…', 'muted');
    const email = document.getElementById('email').value.trim();
    const plain = await generatePlain(email);
    const sel = selectedIndexesFromUI(puzzle.n_bits);
    await encryptCredentials(plain, sel);
    maskDiag(plain); // show masked diagnostics only
    setStatus('Encrypted and stored.', 'ok');
  } catch(e){ setStatus('Error: ' + (e.message||e), 'err'); }
});

document.getElementById('btnDecrypt').addEventListener('click', async ()=>{
  try {
    setStatus('Decrypting…', 'muted');
    const sel = selectedIndexesFromUI(puzzle.n_bits);
    const meta = await decryptCredentials(sel);
    // Download plaintext JSON
    const blob = new Blob([JSON.stringify(meta, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'cbmkt_backup_'+(meta.email||'noemail')+'_'+meta.created_at+'.json';
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    setStatus('Decrypted and downloaded.', 'ok');
  } catch(e){ setStatus('Error: ' + (e.message||e), 'err'); }
});

// --- Nonce + actions ---
async function postJson(url, payload){
  const res = await fetch(url, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  return res.json();
}

let lastNonce = null;

document.getElementById('btnNonce').addEventListener('click', async ()=>{
  const email = document.getElementById('email').value.trim();
  if (!email) return setStatus('Enter email first.', 'err');
  const j = await postJson('issue_nonce.php', { email });
  if (j.success){ lastNonce = j.nonce; setStatus('Nonce issued: '+j.nonce.slice(0,8)+'…', 'ok'); }
  else setStatus('Nonce error: '+(j.error||'unknown'), 'err');
});

document.getElementById('btnActivate').addEventListener('click', async ()=>{
  try {
    if (!lastNonce) return setStatus('Request a nonce first.', 'err');
    const sel = selectedIndexesFromUI(puzzle.n_bits);
    const meta = await decryptCredentials(sel); // to read checksum/email
    const j = await postJson('activate_backup.php', { email: meta.email, metadata: { checksum: meta.checksum }, nonce: lastNonce });
    setStatus(j.success ? 'Activated.' : 'Activate failed: '+(j.error||'unknown'), j.success ? 'ok':'err');
  } catch(e){ setStatus('Error: ' + (e.message||e), 'err'); }
});

document.getElementById('btnMigrate').addEventListener('click', async ()=>{
  try {
    if (!lastNonce) return setStatus('Request a nonce first.', 'err');
    const sel = selectedIndexesFromUI(puzzle.n_bits);
    const meta = await decryptCredentials(sel);
    // Request OTP
    const req = await postJson('request_recovery.php', { email: meta.email });
    if (!req.success) return setStatus('OTP request failed: '+(req.error||'unknown'), 'err');
    const otp = prompt('Enter 6-digit OTP sent to your email:');
    if (!otp) return setStatus('OTP required.', 'err');
    const j = await postJson('migrate_auctions.php', { email: meta.email, checksum: meta.checksum, otp, nonce: lastNonce });
    setStatus(j.success ? ('Migrated '+(j.migrated??0)+' auctions.') : 'Migrate failed: '+(j.error||'unknown'), j.success?'ok':'err');
  } catch(e){ setStatus('Error: ' + (e.message||e), 'err'); }
});
</script>
</body>
</html>

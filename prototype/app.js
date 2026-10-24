"use strict";
// Every value in this file is fictional. No persistence, network, real email or crypto.
const $ = (q) => document.querySelector(q);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const MIN = 60000;
const TYPES = {login:'網站登入', password:'其它密碼', note:'安全備註'};
const PURPOSES = {bind:'驗證信箱', unlock:'解鎖', reset:'重設主密碼', reveal:'顯示／複製密碼', sensitive:'敏感設定'};
const MAIL_STATE = {valid:'有效', used:'已使用', replaced:'已被新碼取代', expired:'已過期', void:'已作廢'};
const OPS = {'export':'匯出備份', 'email-enable':'設定 Email 驗證碼', 'email-change':'變更信箱', 'email-disable':'停用 Email 驗證碼', 'change-master':'變更主密碼'};
const PHASE = {logging_in:'PASS_PW 正在填入帳密並登入', needs_user:'需要你在專用瀏覽器完成網站驗證', logged_in:'已登入，AI 工作中'};
const CLIENTS = ['Claude Code', 'Codex', 'OpenCode', 'Hermes Agent'];
const CSV_ROWS = [
 {name:'示範商店', url:'https://shop.example.com/login', account:'buyer@example.com'},
 {name:'示範新聞', url:'https://news.example.com/login', account:'news@example.com'},
 {name:'示範工作平台', url:'https://work.example.com/login', account:'demo@example.com'}
];
const seed = () => [
 {id:'work', type:'login', name:'示範工作平台', url:'https://work.example.com/login', origin:'https://work.example.com', alias:'工作帳號', account:'demo@example.com', password:'Demo-Only!Work2026', note:'', ai:true, grantMin:240},
 {id:'reading', type:'login', name:'個人閱讀清單', url:'https://reading.example.com/signin', origin:'https://reading.example.com', alias:'個人帳號', account:'reader@example.com', password:'Demo-Only!Read2026', note:'', ai:false},
 {id:'design', type:'login', name:'設計素材庫', url:'https://design.example.com/login', origin:'https://design.example.com', alias:'設計帳號', account:'designer@example.com', password:'Demo-Only!Design2026', note:'', ai:false},
 {id:'wifi', type:'password', name:'家用 Wi-Fi', account:'HOME-DEMO-5G', password:'Demo-Only!WiFi2026', note:'路由器在客廳'},
 {id:'codes', type:'note', name:'示範復原碼', note:'DEMO-1111\nDEMO-2222\nDEMO-3333'}
];
let s, revealTimer, toastTimer, clipTimer, resendTimer, lastView = '';

const now = () => Date.now();
const clock = (t = now()) => new Date(t).toLocaleTimeString('zh-TW', {hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
const stamp = () => new Date().toLocaleString('zh-TW', {hour12:false, month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'});
const item = (id) => s.items.find(i => i.id === id);
const secretOf = (i) => i.type === 'note' ? i.note : i.password;
const secretLabel = (i) => i.type === 'note' ? '內容' : '密碼';
const mask = (a) => a ? a[0] + '***' + a.slice(a.indexOf('@')) : '';
const fresh = () => s.fresh > 0 && now() - s.fresh < MIN;
const grantActive = (id) => (s.grants[id] || 0) > now();
const DURATIONS = [30, 60, 120, 240, 480];
const MAX_GRANT = 720;
const hm = (t) => (new Date(t).toDateString() === new Date().toDateString() ? '' : '明天 ') + new Date(t).toLocaleTimeString('zh-TW', {hour12:false, hour:'2-digit', minute:'2-digit'});
const fmtDur = (m) => m < 60 ? `${m} 分鐘` : `${Math.floor(m / 60)} 小時${m % 60 ? ` ${m % 60} 分鐘` : ''}`;
function durationPicker(selected, key){
 const preset = DURATIONS.includes(selected);
 return `<div class="duration"><label for="dur-${key}">授權時間</label><select id="dur-${key}" class="dur">${DURATIONS.map(m => `<option value="${m}" ${m === selected ? 'selected' : ''}>${fmtDur(m)}</option>`).join('')}<option value="custom" ${preset ? '' : 'selected'}>自訂…</option></select><div class="custom-dur" ${preset ? 'hidden' : ''}><label for="custom-${key}">自訂分鐘數（15–${MAX_GRANT}）</label><input id="custom-${key}" class="dur-custom" type="number" min="15" max="${MAX_GRANT}" step="15" value="${preset ? 90 : selected}"></div><p class="small long-warn" ${selected > 120 ? '' : 'hidden'}>長時間授權期間，AI 可持續操作此帳號；建議用於測試帳號或開發環境。</p><div class="field-error dur-error" role="alert"></div></div>`;
}
// Reads the duration picker inside `box`; returns minutes or null when the custom value is out of range.
function readDuration(box){
 const sel = box.querySelector('.dur');
 const m = sel.value === 'custom' ? Math.round(+box.querySelector('.dur-custom').value) : +sel.value;
 if(!(m >= 15 && m <= MAX_GRANT)){ box.querySelector('.dur-error').textContent = `請輸入 15 到 ${MAX_GRANT} 分鐘。`; return null; }
 return m;
}
const backupStale = () => !s.backup || s.backup.version !== s.dataVersion;
const kv = (k, v) => `<div class="keyvalue"><span>${k}</span>${esc(v)}</div>`;
function rand(n){ const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; }
const randomCode = () => String(rand(1000000)).padStart(6, '0');
function generatePassword(len = 20){ const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+'; let o = ''; for(let k = 0; k < len; k++) o += c[rand(c.length)]; return o; }

function reset(){
 hideSecret(); clearTimeout(resendTimer);
 s = {screen:'setup', tab:'vault', selected:null, master:null, email:null, locked:false, items:seed(), filter:'all', search:'',
  fresh:0, revealed:null, revealUntil:0, verifying:null, pending:[], sessions:[], grants:{}, keepLock:{}, clients:[{id:'c1', name:'Codex'}],
  otp:null, voided:0, pausedUntil:0, sends:[], inbox:[], mailFail:false, backup:null, dataVersion:0, fails:0, waitUntil:0, idle:5, logs:[]};
 closeModal(); render();
}
function note(msg){ $('#toast').textContent = msg; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').textContent = '', 5000); }
function log(msg, result = '完成'){ s.logs.unshift({time:clock(), msg, result}); }
function hideSecret(){ if(s) s.revealed = null; clearInterval(revealTimer); }
function closeModal(){ const m = $('#modal'); if(m.open) m.close(); m.innerHTML = ''; }
function dialog(title, body){ const m = $('#modal'); m.innerHTML = `<h2 id="dialog-title">${title}</h2>${body}`; if(!m.open) m.showModal(); }

// ---------- layout ----------
function shell(content){
 const on = s.screen === 'main' && !s.locked;
 const nav = [['vault','密碼清單'],['ai','AI 代理'],['settings','設定'],['logs','活動紀錄']];
 return `<div class="shell"><aside><div class="logo">PASS_PW</div><div class="sublogo">個人密碼管理器</div><nav>${nav.map(([id,label]) => `<button data-nav="${id}" class="${on && (s.tab === id || (id === 'vault' && s.tab === 'detail')) ? 'active' : ''}" ${on ? '' : 'disabled'}>${label}${id === 'ai' && s.pending.length ? ` · ${s.pending.length}` : ''}</button>`).join('')}</nav><div class="aside-note">密碼只存在這台電腦<br>AI 登入由你核准</div></aside><main>${content}</main></div>`;
}
function header(title, sub){ return `<div class="top"><div><h1>${title}</h1><p class="muted">${sub}</p></div><div class="title-actions"><button data-action="lock">鎖定密碼庫</button><button class="danger" data-action="stop-all">全部鎖定並停止</button></div></div>`; }
function banners(){
 let h = s.sessions.map(x => `<div class="banner ${x.phase === 'needs_user' ? 'warn' : ''}">${esc(x.client)} · ${esc(item(x.itemId)?.name)}：${PHASE[x.phase]}${x.phase === 'logged_in' ? ` · 到 ${hm(x.expiresAt)}` : ''} ${x.phase === 'needs_user' ? `<button class="text" data-action="mfa-done" data-id="${x.id}">模擬我已完成驗證</button>` : ''}<button class="text" data-action="end-session" data-id="${x.id}">停止</button></div>`).join('');
 if(s.pending.length) h += `<div class="banner">有 ${s.pending.length} 筆 AI 登入要求等你確認。<button class="text" data-nav="ai">查看要求</button></div>`;
 return h;
}

// ---------- first run ----------
function steps(n){ return `<ol class="steps">${['設定主密碼','Email 驗證碼（選填）','第一份備份（建議）'].map((t,k) => `<li class="${k === n ? 'current' : k < n ? 'done' : ''}">${k + 1} ${t}</li>`).join('')}</ol>`; }
function masterForm(mode){
 return `<form id="master-form" data-mode="${mode}"><label for="new-master">${mode === 'setup' ? '主密碼' : '新主密碼'}</label><input id="new-master" type="password" autocomplete="off" ${mode === 'setup' ? 'placeholder="演練可用 DemoMaster!2026"' : ''} required><label for="confirm-master">再次輸入</label><input id="confirm-master" type="password" autocomplete="off" required><p class="small muted">至少 12 字元，可以用長句子。PASS_PW 不會保存主密碼本身。</p><div class="field-error" id="master-error" role="alert"></div><div class="form-actions">${mode === 'setup' ? '' : '<button type="button" data-action="cancel-modal">取消</button>'}<button class="primary" type="submit">${mode === 'setup' ? '下一步' : '更新主密碼'}</button></div></form>`;
}
function emailForm(ctx){
 return `<div class="banner warn">若 AI 能讀取這個信箱，請不要啟用 Email 驗證，改只用主密碼。</div><form id="email-form" data-context="${ctx}"><fieldset><legend>寄信設定（你自己的 SMTP）</legend><div class="grid2"><div><label for="smtp-host">SMTP 伺服器</label><input id="smtp-host" value="smtp.example.com" required></div><div><label for="smtp-port">連接埠</label><input id="smtp-port" inputmode="numeric" value="587" required></div></div><label for="smtp-user">寄件帳號</label><input id="smtp-user" value="sender@example.com" required><label for="smtp-pass">應用程式密碼</label><input id="smtp-pass" type="password" value="demo-app-password" autocomplete="off" required></fieldset><label for="email-address">收取驗證碼的信箱</label><input id="email-address" type="email" value="demo@example.com" required><p class="small muted">原型使用示範寄送器，不會連線或寄信；驗證碼顯示在對話框裡的「示範信箱」。</p><details class="small"><summary>啟用後的安全取捨</summary><p>為了在鎖定時也能用驗證碼解鎖，資料金鑰會另外由 Windows 保護一份。同一 Windows 帳號下的程式有機會繞過驗證碼解開資料；在意這點請只用主密碼。</p></details><div class="field-error" id="email-error" role="alert"></div><div class="form-actions">${ctx === 'setup' ? '<button type="button" data-action="skip-email">略過</button>' : '<button type="button" data-action="cancel-modal">取消</button>'}<button class="primary" type="submit">寄送測試驗證碼</button></div></form>`;
}
function backupForm(ctx){
 return `<form id="backup-form" data-context="${ctx}"><label for="backup-pass">備份密碼</label><input id="backup-pass" type="password" autocomplete="off" required><label for="backup-confirm">再次輸入</label><input id="backup-confirm" type="password" autocomplete="off" required><p class="small muted">至少 12 字元，可與主密碼相同。原型不會產生檔案；正式版輸出一個加密的 .passpw 檔。</p><div class="field-error" id="backup-error" role="alert"></div><div class="form-actions">${ctx === 'setup' ? '<button type="button" data-action="skip-backup">稍後再說</button>' : '<button type="button" data-action="cancel-modal">取消</button>'}<button class="primary" type="submit">建立備份</button></div></form>`;
}
function setupView(){
 if(s.screen === 'setup-email') return `<div class="intro">${steps(1)}<h1>要加上 Email 驗證碼嗎？</h1><p class="muted">啟用後，解鎖或顯示密碼時可以改用寄到信箱的 6 位數驗證碼。忘記主密碼時，也能用驗證碼重設。</p><div class="panel">${emailForm('setup')}</div></div>`;
 if(s.screen === 'setup-backup') return `<div class="intro">${steps(2)}<h1>建議先匯出第一份備份</h1><p class="muted">重灌、換電腦或檔案損壞時，可以用備份檔還原。</p><div class="panel">${backupForm('setup')}</div></div>`;
 return `<div class="intro">${steps(0)}<h1>建立你的密碼庫</h1><p class="muted">主密碼是任何情況下都能解開資料的方式，必須設定。</p><div class="panel">${masterForm('setup')}</div></div>`;
}

// ---------- locked ----------
function lockedView(){
 const live = s.sessions.length;
 return `<div class="intro"><div class="lock-icon" aria-hidden="true">▣</div><h1>密碼庫已鎖定</h1><p class="muted">解鎖後 60 秒內，顯示或複製密碼不必再驗證一次。</p>${live ? `<div class="banner warn">已登入的 AI 工作仍可繼續到期限（${live} 個）；鎖定期間 AI 不能填入帳密或提出新登入。<button class="danger" data-action="stop-all">全部鎖定並停止</button></div>` : ''}<div class="panel"><form id="unlock-form"><label for="unlock-pass">主密碼</label><input id="unlock-pass" type="password" autocomplete="off" required><div class="field-error" id="unlock-error" role="alert"></div><div class="form-actions"><button type="submit" class="primary">解鎖</button></div></form>${s.email ? `<div class="divider"><span>或</span></div><button data-action="email-unlock">寄送 Email 驗證碼解鎖</button><p class="small muted">寄至 ${esc(mask(s.email))} · 10 分鐘內有效</p>` : ''}<div class="row wrap links">${s.email ? '<button class="text" data-action="email-reset">忘記主密碼？用 Email 驗證後重設</button>' : ''}<button class="text" data-action="restore">從備份還原</button></div></div></div>`;
}

// ---------- vault ----------
function itemMeta(i){ return i.type === 'login' ? `${new URL(i.origin).hostname} · ${i.alias}` : i.type === 'password' ? (i.account || '其它密碼') : '僅供本人查看'; }
function vaultView(){
 const q = s.search.toLowerCase();
 const list = s.items.filter(i => (s.filter === 'all' || i.type === s.filter) && [i.name, i.origin, i.alias, i.account].join(' ').toLowerCase().includes(q));
 const backup = backupStale() ? `<div class="banner warn">${s.backup ? `備份已過期：${esc(s.backup.date)} 之後有新增或修改。` : '尚未建立備份。'}<button class="text" data-action="export">匯出備份</button></div>` : '';
 const chips = [['all','全部'], ...Object.entries(TYPES)].map(([k,l]) => `<button class="chip ${s.filter === k ? 'on' : ''}" aria-pressed="${s.filter === k}" data-filter="${k}">${l}</button>`).join('');
 const rows = list.map(i => `<article class="panel item"><div class="icon" aria-hidden="true">${esc(i.name[0])}</div><div class="item-body"><h3>${esc(i.name)}</h3><div class="small muted">${esc(TYPES[i.type])} · ${esc(itemMeta(i))}</div></div><div class="item-actions"><span class="pill ${i.ai ? 'blue' : ''}">${i.ai ? 'AI 可要求登入' : '僅供本人'}</span><button data-action="open" data-id="${i.id}">查看</button></div></article>`).join('');
 return `${header('密碼清單','網站帳密與其它密碼，加密保存在這台電腦。')}${banners()}${backup}<div class="stats"><div class="panel stat"><strong>${s.items.length}</strong><span>已保存項目</span></div><div class="panel stat"><strong>${s.items.filter(i => i.ai).length}</strong><span>開放 AI 代理登入的網站</span></div><div class="panel stat"><strong>${s.sessions.length}</strong><span>進行中的 AI 工作</span></div></div><div class="row between toolbar wrap"><input id="search" type="search" aria-label="搜尋名稱、網址或帳號" placeholder="搜尋名稱、網址或帳號" value="${esc(s.search)}"><button class="primary" data-action="add">＋ 新增</button></div><div class="chips" role="group" aria-label="類型篩選">${chips}</div><div class="items">${rows || '<div class="panel empty"><h2>找不到符合的項目</h2><p class="muted">試試其他名稱、網址或帳號，或切換類型。</p><button data-action="clear-search">清除搜尋與篩選</button></div>'}</div>`;
}
function detailView(){
 const i = item(s.selected);
 if(!i){ s.tab = 'vault'; return vaultView(); }
 const shown = s.revealed === i.id, left = Math.max(0, Math.ceil((s.revealUntil - now()) / 1000));
 const hint = shown ? `<span id="reveal-count">${left}</span> 秒後自動遮罩；切換畫面、視窗失焦或鎖定時立即遮罩。` : fresh() ? '你剛通過驗證，60 秒內可直接顯示或複製。' : '顯示或複製前需要驗證本人。';
 const secret = `<label>${secretLabel(i)}</label><div class="password-view ${i.type === 'note' ? 'note-view' : ''}">${shown ? esc(secretOf(i)) : '••••••••••••'}</div><p class="small muted">${hint}</p><div class="row wrap"><button data-action="${shown ? 'hide' : 'reveal'}">${shown ? '隱藏' : '顯示'}</button><button data-action="copy">複製</button></div>`;
 const fields = i.type === 'login' ? kv('帳號別名', i.alias) + kv('帳號', i.account) : i.type === 'password' && i.account ? kv('帳號', i.account) : '';
 const side = i.type === 'login'
  ? `<h2>AI 代理登入</h2><span class="pill ${i.ai ? 'blue' : ''}">${i.ai ? '允許 AI 提出登入要求' : '未開放 AI'}</span>${kv('登入網址', i.url)}${kv('登入欄位', i.selectors ? '已指定欄位' : '自動辨識')}<p class="muted small">開啟後，已配對的 AI 只看得到名稱、網址與帳號別名。每次登入由你核准，密碼由 PASS_PW 直接填進網頁。</p>${kv('AI 預設授權時間', fmtDur(i.grantMin || 30))}${grantActive(i.id) ? `<div class="banner">此網站已授權到 ${hm(s.grants[i.id])}${s.keepLock[i.id] ? '（Windows 鎖定時保留）' : ''}<button class="text" data-action="extend-grant" data-id="${i.id}">延長</button><button class="text" data-action="revoke-grant" data-id="${i.id}">撤銷</button></div>` : ''}`
  : `<h2>使用範圍</h2><p class="muted">${TYPES[i.type]}只供你本人查看，AI 無法使用。</p>`;
 return `${header(esc(i.name), esc(TYPES[i.type] + (i.origin ? ' · ' + i.origin : '')))}${banners()}<button class="text" data-nav="vault">← 返回清單</button><div class="details-grid"><div class="panel"><h2>${i.type === 'note' ? '備註內容' : '帳號與密碼'}</h2>${fields}${secret}${i.type !== 'note' && i.note ? kv('備註', i.note) : ''}</div><div class="panel">${side}<div class="row wrap"><button data-action="edit" data-id="${i.id}">編輯</button><button class="danger" data-action="delete" data-id="${i.id}">刪除</button></div></div></div>`;
}

// ---------- AI ----------
function approveButtons(id, where = "tab"){
 const r = s.pending.find(p => p.id === id), def = item(r.itemId).grantMin || 30;
 return `<div class="approve"><fieldset><legend>允許此網站一段時間</legend><p class="small muted">期間內同一 AI 再要求登入不必重新核准；可隨時延長或撤銷。</p>${durationPicker(def, where + id)}<label class="check"><input type="checkbox" class="keep-lock">Windows 鎖定時保留這個網站的 AI 工作</label><p class="small muted">只保留已登入的工作；鎖定期間仍不能填入帳密。你離開座位時 AI 仍在操作此帳號。</p><div class="form-actions"><button data-action="approve-site" data-id="${id}">允許此網站</button></div></fieldset><div class="form-actions wrap"><button data-action="reject" data-id="${id}">拒絕</button><button class="primary" data-action="approve-once" data-id="${id}">允許這次（15 分鐘）</button></div></div>`;
}
function grantsView(){
 const list = Object.keys(s.grants).filter(grantActive).map(id => `<div class="row between wrap client"><div><strong>${esc(item(id)?.name)}</strong><div class="small muted">授權到 ${hm(s.grants[id])}${s.keepLock[id] ? ' · Windows 鎖定時保留' : ''}</div></div><div class="row wrap"><button data-action="extend-grant" data-id="${id}">延長</button><button class="danger" data-action="revoke-grant" data-id="${id}">撤銷</button></div></div>`).join('');
 return list ? `<h2>網站授權</h2><div class="panel">${list}</div>` : '';
}
function extendDialog(id){
 const i = item(id);
 dialog('延長網站授權', `<p>「${esc(i.name)}」目前授權到 ${hm(s.grants[id])}。選擇的時間會加在目前的到期時刻之後；從現在起算最多 12 小時。</p><div class="approve">${durationPicker(60, 'extend')}<div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="extend-confirm" data-id="${id}">延長</button></div></div>`);
}
// Ends grants and AI work whose time is up (the real app does this in the core).
function expireTick(){
 if(!s) return;
 const t = now(); let changed = false;
 Object.keys(s.grants).forEach(id => { if(s.grants[id] <= t){ delete s.grants[id]; delete s.keepLock[id]; log(`「${item(id)?.name}」網站授權到期`); changed = true; } });
 const ended = s.sessions.filter(x => x.expiresAt <= t);
 if(ended.length){ s.sessions = s.sessions.filter(x => x.expiresAt > t); ended.forEach(x => log(`${x.client} 的 AI 工作到期`, '已停止')); changed = true; }
 if(changed) render();
}
function aiView(){
 const req = s.pending.map(r => { const i = item(r.itemId); return `<div class="panel request"><span class="pill warn">等待你的核准</span><h2>${esc(r.client)} 想登入「${esc(i.name)}」</h2><p>${esc(i.alias)} · ${esc(i.origin)}</p><p class="muted small">核准後 PASS_PW 會開啟專用瀏覽器並自己填入帳密；AI 之後只能用受限工具操作頁面，拿不到密碼。2 分鐘內未回應會自動拒絕。</p>${approveButtons(r.id)}</div>`; }).join('') || '<div class="panel empty">目前沒有待核准的登入要求。</div>';
 const ses = s.sessions.map(x => { const i = item(x.itemId); return `<div class="panel"><div class="row between wrap"><div><h3>${esc(i?.name)} · ${esc(i?.alias)}</h3><p class="muted">${esc(x.client)} · ${PHASE[x.phase]}${x.phase === 'logged_in' ? ` · 到 ${hm(x.expiresAt)}` : ''}</p></div><div class="row wrap">${x.phase === 'needs_user' ? `<button class="primary" data-action="mfa-done" data-id="${x.id}">模擬我已完成網站驗證</button>` : ''}<button class="danger" data-action="end-session" data-id="${x.id}">停止</button></div></div></div>`; }).join('') || '<div class="panel empty">目前沒有 AI 工作。</div>';
 return `${header('AI 代理','AI 提出登入要求，由你核准；帳密由 PASS_PW 填入網頁，不交給 AI。')}<div class="stack"><h2>待核准要求</h2>${req}<h2>進行中的工作</h2>${ses}${grantsView()}<div class="panel"><div class="row between wrap"><div><h3>已配對的 AI 連線</h3><p class="muted small">${s.clients.length ? s.clients.map(c => esc(c.name)).join('、') + ' · 與 PASS_PW 同一 Windows 帳號（未隔離）' : '尚未配對'}</p></div><button data-nav="settings">管理連線</button></div></div></div>`;
}

// ---------- settings & logs ----------
function settingsView(){
 const bk = s.backup ? `${backupStale() ? '備份已過期' : '備份為最新'} · ${esc(s.backup.date)} · ${s.backup.count} 筆` : '尚未建立備份';
 const clients = s.clients.map(c => `<div class="row between wrap client"><div><strong>${esc(c.name)}</strong><div class="small muted">Windows 帳號：與 PASS_PW 相同</div></div><div class="row wrap"><span class="pill warn">未隔離</span><button class="danger" data-action="revoke-client" data-id="${c.id}">撤銷</button></div></div>`).join('') || '<p class="muted">尚未配對任何 AI。</p>';
 return `${header('設定','驗證方式、備份與 AI 連線。')}${banners()}<div class="details-grid"><div class="panel"><h2>本人驗證</h2><div class="keyvalue"><span>主密碼</span>已設定 <button class="text" data-action="change-master">變更主密碼</button></div><div class="keyvalue"><span>Email 驗證碼</span>${s.email ? `已啟用 · ${esc(mask(s.email))} <button class="text" data-action="email-change">變更信箱</button><button class="text" data-action="email-disable">停用</button>` : '未啟用 <button class="text" data-action="email-enable">設定 Email 驗證碼</button>'}</div><label for="idle">閒置自動鎖定</label><select id="idle">${[1,5,15,30].map(m => `<option value="${m}" ${s.idle === m ? 'selected' : ''}>${m} 分鐘</option>`).join('')}</select><p class="small muted">變更主密碼、信箱、停用 Email、匯出備份時都要重新驗證，不沿用 60 秒內的免驗證。</p></div><div class="panel"><h2>備份與匯入</h2><p><span class="pill ${backupStale() ? 'warn' : 'good'}">${bk}</span></p><div class="row wrap"><button data-action="export">匯出備份</button><button data-action="restore">從備份還原</button></div><p class="small muted">還原會另建新密碼庫，不覆寫目前資料。</p><div class="keyvalue"><span>從瀏覽器匯入</span>Chrome／Edge 匯出的密碼 CSV</div><p><button data-action="import">匯入 CSV</button></p></div><div class="panel span2"><h2>AI 連線</h2>${clients}<p class="small muted">「未隔離」表示同一 Windows 帳號下、能執行指令的 AI 理論上可以攻擊 PASS_PW 程序；PASS_PW 保證的是密碼不經由工具進入 AI 對話。需要更強保護時，可讓 AI 在另一個 Windows 帳號執行。</p><button class="primary" data-action="add-client">新增 AI 連線</button></div></div>`;
}
function logsView(){ return `${header('活動紀錄','記錄時間、動作與結果；不記錄密碼或驗證碼。')}<div class="panel">${s.logs.map(l => `<div class="activity"><span>${esc(l.time)}</span><span>${esc(l.msg)}</span><span>${esc(l.result)}</span></div>`).join('') || '目前沒有活動紀錄。'}</div>`; }

function renderLab(){
 const sent = s.sends.filter(t => now() - t < 60 * MIN).length;
 $('#lab-state').textContent = `寄信失敗模擬：${s.mailFail ? '開啟' : '關閉'} · 本小時已寄 ${sent}/5 封 · Email 驗證${s.pausedUntil > now() ? '暫停中' : '可用'} · AI 連線 ${s.clients.length} 個`;
}
function render(){
 const views = {detail:detailView, ai:aiView, settings:settingsView, logs:logsView};
 const body = s.screen !== 'main' ? setupView() : s.locked ? lockedView() : (views[s.tab] || vaultView)();
 $('#app').innerHTML = shell(body);
 renderLab();
 const view = [s.screen, s.locked, s.tab, s.selected].join(':');
 if(view !== lastView) window.scrollTo({top:0, behavior:'instant'});
 lastView = view;
}

// ---------- verification ----------
function checkMaster(v, err){
 const t = now();
 if(t < s.waitUntil){ err.textContent = `請等 ${Math.ceil((s.waitUntil - t) / 1000)} 秒再試。`; return false; }
 if(v === s.master){ s.fails = 0; return true; }
 s.fails++; const d = Math.min(2 ** (s.fails - 1), 30); s.waitUntil = t + d * 1000;
 err.textContent = `主密碼不正確。請等 ${d} 秒再試。`; log('主密碼錯誤', '已拒絕'); return false;
}
function requireAuth(kind, target, always){ s.verifying = {kind, target}; if(!always && fresh()) return complete(); verifyDialog(); }
function verifyDialog(){
 const v = s.verifying, i = v.kind === 'reveal' ? item(v.target.id) : null;
 const desc = i ? `要${v.target.act === 'copy' ? '複製' : '顯示'}「${esc(i.name)}」的${secretLabel(i)}，請先確認是你本人。` : `${OPS[v.target.op]}需要重新驗證本人。`;
 dialog('確認是你本人', `<p>${desc}</p><form id="verify-form"><label for="verify-pass">主密碼</label><input id="verify-pass" type="password" autocomplete="off" required><div id="verify-error" class="field-error" role="alert"></div>${s.email ? '<button type="button" class="text" data-action="verify-email">改寄 Email 驗證碼</button>' : ''}<div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button class="primary" type="submit">驗證</button></div></form>`);
 $('#verify-pass').focus();
}
function complete(){
 const v = s.verifying; s.verifying = null; closeModal();
 if(v.kind === 'reveal') return v.target.act === 'copy' ? copySecret(v.target.id) : showSecret(v.target.id);
 const op = v.target.op;
 if(op === 'export') dialog('匯出備份', backupForm('settings'));
 if(op === 'email-enable' || op === 'email-change') dialog(OPS[op], emailForm('settings'));
 if(op === 'email-disable') dialog('停用 Email 驗證碼？', '<p>停用後會刪除 Email 的解鎖路徑與待驗證的驗證碼，之後只能用主密碼。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="danger" data-action="email-disable-confirm">停用</button></div>');
 if(op === 'change-master') dialog('變更主密碼', masterForm('change'));
}
function failActions(p){
 return `<div class="form-actions wrap">${['reset','bind'].includes(p) ? '' : '<button data-action="use-master">改用主密碼</button>'}${['unlock','reset'].includes(p) ? '<button data-action="restore">從備份還原</button>' : ''}<button class="primary" data-action="cancel-modal">返回</button></div>`;
}
function sendCode(purpose, target = {}){
 const t = now();
 if(s.pausedUntil > t) return dialog('Email 驗證暫停中', `<p>連續 3 組驗證碼作廢，Email 驗證暫停到 ${clock(s.pausedUntil)}。</p>${failActions(purpose)}`);
 if(s.sends.filter(x => t - x < 60 * MIN).length >= 5) return dialog('已達寄送上限', `<p>本小時已寄出 5 封驗證碼，請稍後再試。</p>${failActions(purpose)}`);
 if(s.otp && s.otp.purpose === purpose && t - s.otp.sent < MIN) return note('重新寄送需間隔 60 秒。');
 if(s.mailFail){ log(`寄送 Email 驗證碼（${PURPOSES[purpose]}）`, '寄送失敗'); return dialog('寄信失敗', `<p>寄信服務回報錯誤，這次沒有產生驗證碼。請稍後再試，或改用其它方式。</p>${failActions(purpose)}`); }
 s.inbox.forEach(m => { if(m.state === 'valid') m.state = 'replaced'; });
 const mail = {code:randomCode(), purpose, time:clock(t), state:'valid'};
 s.inbox.unshift(mail); s.sends.push(t);
 s.otp = {purpose, target, to:purpose === 'bind' ? target.addr : s.email, mail, sent:t, expires:t + 10 * MIN, attempts:0};
 log(`寄送 Email 驗證碼（${PURPOSES[purpose]}）`, '已接受寄送');
 renderLab(); codeDialog();
}
function codeDialog(msg = ''){
 const o = s.otp, wait = Math.max(0, MIN - (now() - o.sent));
 const inbox = s.inbox.slice(0, 4).map(m => `<li><code>${m.code}</code> · ${PURPOSES[m.purpose]} · ${m.time} · ${MAIL_STATE[m.state]}</li>`).join('');
 dialog('輸入 Email 驗證碼', `<p>已寄到 ${esc(mask(o.to))}（${PURPOSES[o.purpose]}）。</p><p class="small muted">10 分鐘內有效，只能使用一次；重新寄送後舊碼立即失效。</p><form id="code-form"><label for="code">6 位數驗證碼</label><input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><div class="field-error" id="code-error" role="alert">${esc(msg)}</div><div class="row wrap"><button type="button" data-action="resend" ${wait ? 'disabled' : ''}>重新寄送</button>${['bind','reset'].includes(o.purpose) ? '' : '<button type="button" class="text" data-action="use-master">改用主密碼</button>'}<button type="button" class="text" data-action="cancel-modal">取消</button></div><div class="form-actions"><button type="submit" class="primary">驗證</button></div></form><details class="small demo-box" open><summary>示範信箱（僅演練；正式版是你的真實信箱）</summary><ul>${inbox}</ul><div class="row wrap"><button type="button" data-lab="otp-expire">模擬驗證碼過期</button><button type="button" data-lab="otp-resend">模擬 60 秒已過</button></div></details>`);
 clearTimeout(resendTimer);
 if(wait) resendTimer = setTimeout(() => { const b = $('[data-action="resend"]'); if(b) b.disabled = false; }, wait);
 $('#code').focus();
}
function onCode(o){
 if(o.purpose === 'bind'){
  s.email = o.to; log('啟用 Email 驗證碼', mask(o.to)); closeModal();
  if(o.target.ctx === 'setup') s.screen = 'setup-backup'; else note(`Email 驗證碼已啟用：${mask(o.to)}`);
  return render();
 }
 if(o.purpose === 'unlock') return finishUnlock();
 if(o.purpose === 'reset'){ finishUnlock(); return dialog('設定新主密碼', `<p>已用 Email 驗證碼解鎖。請設定新的主密碼，舊主密碼之後不能再解鎖。</p>${masterForm('reset')}`); }
 s.fresh = now(); complete();
}
function finishUnlock(){ s.locked = false; s.tab = 'vault'; s.fresh = now(); s.fails = 0; log('解鎖密碼庫'); closeModal(); render(); }
// keepFlagged: Windows lock keeps logged-in work on sites granted with "keep on Windows lock".
function lock(all, reason, keepFlagged){
 hideSecret(); closeModal(); s.verifying = null; s.otp = null; s.locked = true; s.fresh = 0;
 if(s.pending.length){ log(`取消 ${s.pending.length} 筆待核准要求`, '已取消'); s.pending = []; }
 if(all){
  const kept = keepFlagged ? s.sessions.filter(x => x.phase === 'logged_in' && s.keepLock[x.itemId] && grantActive(x.itemId)) : [];
  const keep = [...new Set(kept.map(x => x.itemId))];
  const grants = {}, flags = {}; keep.forEach(id => { grants[id] = s.grants[id]; flags[id] = true; });
  if(s.sessions.length > kept.length) log(`停止 ${s.sessions.length - kept.length} 個 AI 工作`, '已停止');
  s.sessions = kept; s.grants = grants; s.keepLock = flags;
  if(kept.length) log(`保留 ${kept.length} 個已登入的 AI 工作（Windows 鎖定時保留）`, '鎖定期間不能填入帳密');
 }
 else {
  const before = s.sessions.length; s.sessions = s.sessions.filter(x => x.phase === 'logged_in');
  if(before > s.sessions.length) log('取消未完成的 AI 登入', '已取消');
 }
 log(reason); render();
}

// ---------- secrets ----------
function showSecret(id){
 hideSecret(); const i = item(id); s.revealed = id; s.revealUntil = now() + 30000;
 log(`顯示「${i.name}」的${secretLabel(i)}`); render();
 revealTimer = setInterval(() => {
  const left = Math.ceil((s.revealUntil - now()) / 1000);
  if(left <= 0){ hideSecret(); render(); return; }
  const el = $('#reveal-count'); if(el) el.textContent = left;
 }, 250);
}
async function copySecret(id){
 const i = item(id);
 // Prototype fallback for browsers that refuse the async clipboard API; the desktop app uses the Windows clipboard API.
 const legacyCopy = (text) => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.append(t); t.select(); const ok = document.execCommand('copy'); t.remove(); return ok; };
 let ok = false;
 try { await navigator.clipboard.writeText(secretOf(i)); ok = true; } catch { ok = legacyCopy(secretOf(i)); }
 if(ok){
  clearTimeout(clipTimer); clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => legacyCopy(' ')), 30000);
  log(`複製「${i.name}」的${secretLabel(i)}`); note('已複製，30 秒後清除剪貼簿。');
 } else note('瀏覽器拒絕寫入剪貼簿（原型限制）。');
 render();
}

// ---------- items ----------
function editForm(type, id){
 const i = id ? item(id) : null; type = i?.type || type;
 const pw = (label, req) => `<label for="item-pass">${label}</label><div class="row pw-row"><input id="item-pass" type="password" autocomplete="new-password" ${req ? 'required' : ''}><button type="button" data-action="gen">產生密碼</button></div><label class="check"><input id="show-pass" type="checkbox">顯示輸入內容</label>`;
 const pwLabel = i ? '替換密碼（留白保留原密碼）' : '密碼';
 let f = `<label for="item-name">名稱</label><input id="item-name" value="${esc(i?.name)}" required>`;
 if(type === 'login') f += `<label for="item-url">登入網址（HTTPS）</label><input id="item-url" type="url" value="${esc(i?.url)}" placeholder="https://example.com/login" required><label for="item-alias">帳號別名（AI 看得到）</label><input id="item-alias" value="${esc(i?.alias)}" placeholder="例如：工作帳號" required><label for="item-account">帳號</label><input id="item-account" value="${esc(i?.account)}" autocomplete="off" required>${pw(pwLabel, !i)}<label for="item-note">備註</label><input id="item-note" value="${esc(i?.note)}"><label class="check"><input id="item-ai" type="checkbox" ${i?.ai ? 'checked' : ''}>允許已配對的 AI 提出登入要求（每次仍需你核准）</label><label for="item-grant">AI 預設授權時間</label><select id="item-grant">${DURATIONS.map(m => `<option value="${m}" ${m === (i?.grantMin || 30) ? 'selected' : ''}>${fmtDur(m)}</option>`).join('')}</select><p class="small muted">核准「允許此網站」時預先選取這個時間，當下仍可改。開發用網站可設長一點。</p><details class="small"><summary>登入欄位（進階，自動辨識失敗時才需要）</summary><label for="sel-user">帳號欄位選擇器</label><input id="sel-user" value="${esc(i?.selectors?.user)}" placeholder="自動辨識"><label for="sel-pass">密碼欄位選擇器</label><input id="sel-pass" value="${esc(i?.selectors?.pass)}" placeholder="自動辨識"></details>`;
 if(type === 'password') f += `<label for="item-account">帳號或識別（選填）</label><input id="item-account" value="${esc(i?.account)}" autocomplete="off">${pw(pwLabel, !i)}<label for="item-note">備註</label><input id="item-note" value="${esc(i?.note)}">`;
 if(type === 'note') f += `<label for="item-content">${i ? '替換內容（留白保留原內容）' : '內容'}</label><textarea id="item-content" rows="5" ${i ? '' : 'required'}></textarea>`;
 dialog(`${i ? '編輯' : '新增'}${TYPES[type]}`, `<form id="item-form" data-id="${i?.id || ''}" data-type="${type}">${f}<div class="field-error" id="item-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button type="submit" class="primary">儲存</button></div></form>`);
}
function stopItem(id, reason){
 const n = s.sessions.filter(x => x.itemId === id).length + s.pending.filter(r => r.itemId === id).length;
 s.sessions = s.sessions.filter(x => x.itemId !== id); s.pending = s.pending.filter(r => r.itemId !== id); delete s.grants[id]; delete s.keepLock[id];
 if(n) log(`停止「${item(id)?.name}」相關 AI 工作`, reason);
}
function importDialog(){
 const rows = CSV_ROWS.map(r => ({...r, dup:s.items.some(i => i.type === 'login' && i.origin === new URL(r.url).origin && i.account === r.account)}));
 const n = rows.filter(r => !r.dup).length;
 dialog('匯入 CSV', `<p>已選取演練檔案 chrome-passwords-demo.csv（${rows.length} 列）。</p><table class="preview"><thead><tr><th>名稱</th><th>網址</th><th>帳號</th><th>處理</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(new URL(r.url).hostname)}</td><td>${esc(r.account)}</td><td>${r.dup ? '已存在，略過' : '新增'}</td></tr>`).join('')}</tbody></table><p class="small muted">匯入的網站預設不開放 AI。匯入完成後，請刪除這個明文 CSV 檔。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="import-confirm" ${n ? '' : 'disabled'}>${n ? `匯入 ${n} 筆` : '沒有可匯入的項目'}</button></div>`);
}
function restoreDialog(){
 hideSecret();
 dialog('從備份還原', `<p>已選取演練檔案 PASS_PW-demo.passpw。先檢查檔案，確認後另建新密碼庫，不覆寫目前資料。</p><form id="restore-form"><label for="restore-pass">備份密碼</label><input id="restore-pass" type="password" autocomplete="off" required><p class="small muted">演練：DemoBackup!2026，或本次演練匯出時設定的備份密碼。</p><div class="field-error" id="restore-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button type="submit" class="primary">檢查備份</button></div></form>`);
}
function pairDialog(){
 const code = `${randomCode().slice(0,4)}-${randomCode().slice(0,4)}`;
 const snippet = `{\n  "mcpServers": {\n    "passpw": {\n      "command": "C:\\\\Program Files\\\\PASS_PW\\\\passpw-mcp.exe",\n      "args": ["--pair", "${code}"]\n    }\n  }\n}`;
 dialog('新增 AI 連線', `<label for="client-name">AI 用戶端</label><select id="client-name">${CLIENTS.map(c => `<option>${c}</option>`).join('')}</select><p>把下面設定加入該 AI 用戶端的 MCP 設定：</p><pre class="snapshot">${esc(snippet)}</pre><p class="small muted">配對碼 10 分鐘內有效、只能使用一次（原型不檢查）。原型不會啟動或連接任何 AI。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="pair-done">模擬 AI 完成配對</button></div>`);
}

// ---------- AI simulation ----------
function aiRequest(){
 const c = s.clients[0];
 if(!c) return note('尚無已配對的 AI 連線。');
 const i = s.items.find(x => x.type === 'login' && x.ai && !s.sessions.some(z => z.itemId === x.id) && !s.pending.some(r => r.itemId === x.id));
 if(!s.items.some(x => x.ai)){ log(`${c.name} 呼叫 list_logins`, '空清單'); return note('沒有開放 AI 代理登入的網站，AI 看到空清單。'); }
 if(!i) return note('開放 AI 的網站都已有要求或工作進行中。');
 if(s.locked){ log(`${c.name} 要求登入「${i.name}」`, 'vault_locked'); return note('密碼庫已鎖定：AI 收到 vault_locked，不會排入待核准。'); }
 if(grantActive(i.id)){ log(`${c.name} 要求登入「${i.name}」`, `網站授權內自動允許（到 ${hm(s.grants[i.id])}）`); return startSession({clientId:c.id, client:c.name}, i, s.grants[i.id]); }
 const r = {id:'r' + now(), clientId:c.id, client:c.name, itemId:i.id};
 s.pending.push(r); log(`${c.name} 要求登入「${i.name}」`, '等待核准'); s.tab = 'ai'; render();
 dialog('AI 登入要求', `<p><strong>${esc(r.client)}</strong> 想登入：</p>${kv('網站', i.name)}${kv('帳號', i.alias)}${kv('網址', i.origin)}<p class="small muted">帳密由 PASS_PW 填入專用瀏覽器，AI 拿不到密碼。2 分鐘內未回應會自動拒絕。</p>${approveButtons(r.id, "modal")}`);
}
function decide(id, how, minutes, keepLock){
 const r = s.pending.find(p => p.id === id); closeModal();
 if(!r) return;
 s.pending = s.pending.filter(p => p !== r); const i = item(r.itemId);
 if(how === 'reject'){ log(`拒絕 ${r.client} 登入「${i.name}」`, 'denied'); return render(); }
 const until = now() + (how === 'site' ? minutes : 15) * MIN;
 if(how === 'site'){ s.grants[i.id] = until; if(keepLock) s.keepLock[i.id] = true; else delete s.keepLock[i.id]; }
 log(`核准 ${r.client} 登入「${i.name}」`, how === 'site' ? `此網站 ${fmtDur(minutes)}，到 ${hm(until)}${keepLock ? '，Windows 鎖定時保留' : ''}` : `這次 15 分鐘，到 ${hm(until)}`);
 startSession(r, i, until);
}
function startSession(r, i, expiresAt){
 const x = {id:'x' + now(), clientId:r.clientId, client:r.client, itemId:i.id, phase:'logging_in', expiresAt};
 s.sessions.push(x); render();
 setTimeout(() => { if(s.sessions.includes(x) && x.phase === 'logging_in'){ x.phase = 'needs_user'; log(`「${i.name}」要求網站驗證`, '等待本人'); render(); } }, 1500);
}
function lab(l){
 if(l === 'reset') return reset();
 if(l === 'mail'){ s.mailFail = !s.mailFail; return renderLab(); }
 if(l === 'hour'){ s.sends = []; note('已模擬過了一小時，寄送次數歸零。'); return renderLab(); }
 if(l === 'unpause'){ s.pausedUntil = 0; s.voided = 0; note('Email 驗證暫停已結束。'); return renderLab(); }
 if(l === 'otp-expire'){ if(!s.otp) return note('目前沒有待驗證的驗證碼。'); s.otp.expires = 0; if(s.otp.mail.state === 'valid') s.otp.mail.state = 'expired'; return codeDialog('（模擬）驗證碼已過期。'); }
 if(l === 'otp-resend'){ if(!s.otp) return; s.otp.sent -= MIN; return codeDialog(); }
 if(s.screen !== 'main') return note('請先完成首次設定。');
 const x = s.sessions.find(z => z.phase === 'logged_in'), i = x && item(x.itemId);
 const needSession = () => note('需要一個「已登入」的 AI 工作：先模擬 AI 登入要求並完成網站驗證。');
 if(l === 'request') return aiRequest();
 if(l === 'approve-timeout'){ if(!s.pending.length) return note('沒有待核准要求。'); s.pending.forEach(r => log(`${r.client} 的登入要求`, '逾時自動拒絕')); s.pending = []; closeModal(); return render(); }
 if(l === 'snapshot'){
  if(!x) return needSession();
  log(`${x.client} 呼叫 snapshot`, '已過濾');
  const shot = `頁面：${i.name} – 帳號設定\n網址：${i.origin}/account\n[1] 按鈕「顯示密碼」\n[2] 密碼欄位（值不提供）\n[3] 文字欄位「顯示名稱」= 示範使用者\n文字：「你目前的密碼是 ●●●（已遮蔽）」\n[4] 按鈕「儲存」`;
  return dialog('AI 收到的頁面快照（示範）', `<p class="small muted">這個示範頁面有「顯示密碼」按鈕，而且有一段文字直接寫出已存密碼。AI 收到的內容如下：</p><pre class="snapshot">${esc(shot)}</pre><p class="small muted">密碼欄位不提供值；頁面文字中與已存密碼相同的字串一律遮蔽。沒有執行 JavaScript、讀 Cookie 或截圖的工具。</p><div class="form-actions"><button class="primary" data-action="cancel-modal">關閉</button></div>`);
 }
 if(l === 'fill-ok'){
  if(!x) return needSession();
  if(s.locked){ log(`${x.client} 呼叫 fill_credentials`, 'vault_locked'); return note('密碼庫已鎖定：fill_credentials 回 vault_locked，沒有填入。'); }
  log(`${x.client} 呼叫 fill_credentials（${new URL(i.origin).hostname}）`, 'filled');
  return note('網址相符，PASS_PW 已填入帳密；AI 只收到 filled。');
 }
 if(l === 'fill-bad'){
  if(!x) return needSession();
  const host = new URL(i.origin).hostname + '.evil.test';
  log(`${x.client} 呼叫 fill_credentials（${host}）`, 'origin_mismatch');
  return note(`目前網址 ${host} 與項目不符，拒絕填入。`);
 }
 if(l === 'type-pw'){ if(!x) return needSession(); log(`${x.client} 對密碼欄位呼叫 type`, '已拒絕'); return note('密碼欄位不能用 type 輸入，需改用 fill_credentials。'); }
 if(l === 'expire-session'){ if(!s.sessions.length && !Object.keys(s.grants).length) return note('沒有 AI 工作或網站授權。'); s.sessions.forEach(x => x.expiresAt = 0); Object.keys(s.grants).forEach(id => s.grants[id] = 0); return expireTick(); }
 if(l === 'idle') return lock(false, '閒置自動鎖定');
 if(l === 'winlock') return lock(true, 'Windows 鎖定', true);
 if(l === 'sleep') return lock(true, '電腦休眠：全部鎖定並停止');
 if(l === 'stale'){ s.fresh = 0; note('已模擬超過 60 秒，下一次顯示或複製需要驗證。'); return render(); }
}

// ---------- events ----------
const actions = {
 'skip-email': () => { s.screen = 'setup-backup'; render(); },
 'skip-backup': () => { s.screen = 'main'; s.fresh = now(); log('建立密碼庫', '尚未備份'); render(); },
 'cancel-modal': () => { s.verifying = null; closeModal(); },
 'lock': () => lock(false, '鎖定密碼庫'),
 'stop-all': () => lock(true, '全部鎖定並停止'),
 'email-unlock': () => sendCode('unlock'),
 'email-reset': () => sendCode('reset'),
 'resend': () => sendCode(s.otp.purpose, s.otp.target),
 'verify-email': () => sendCode(s.verifying.kind, s.verifying.target),
 'use-master': () => { if(s.verifying) return verifyDialog(); closeModal(); $('#unlock-pass')?.focus(); },
 'restore': restoreDialog,
 'restore-confirm': () => { closeModal(); log('從備份另建密碼庫（演練）', '未覆寫'); note('已模擬另建新密碼庫；目前的密碼庫保持不變。'); render(); },
 'add': () => dialog('要新增什麼？', `<div class="type-choice">${Object.entries(TYPES).map(([k,l]) => `<button data-action="new-type" data-type="${k}">${l}<br><small>${k === 'login' ? '網站帳號與密碼，可開放 AI 代理登入' : k === 'password' ? 'Wi-Fi、軟體授權、裝置 PIN 等' : '復原碼等需要保密的文字'}</small></button>`).join('')}</div><div class="form-actions"><button data-action="cancel-modal">取消</button></div>`),
 'new-type': (b) => editForm(b.dataset.type),
 'open': (b) => { hideSecret(); s.selected = b.dataset.id; s.tab = 'detail'; render(); },
 'edit': (b) => { hideSecret(); render(); editForm(null, b.dataset.id); },
 'delete': (b) => dialog('刪除這個項目？', `<p>刪除「${esc(item(b.dataset.id).name)}」後，相關的 AI 授權與工作會一併停止。舊備份裡仍會有這筆資料。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="danger" data-action="delete-confirm" data-id="${b.dataset.id}">刪除</button></div>`),
 'delete-confirm': (b) => { const id = b.dataset.id, name = item(id).name; stopItem(id, '項目已刪除'); s.items = s.items.filter(i => i.id !== id); s.dataVersion++; s.tab = 'vault'; log(`刪除「${name}」`); closeModal(); render(); },
 'reveal': () => requireAuth('reveal', {id:s.selected, act:'show'}),
 'copy': () => requireAuth('reveal', {id:s.selected, act:'copy'}),
 'hide': () => { hideSecret(); render(); },
 'gen': () => { const p = $('#item-pass'); p.value = generatePassword(); p.type = 'text'; $('#show-pass').checked = true; note('已產生 20 字元隨機密碼。'); },
 'clear-search': () => { s.search = ''; s.filter = 'all'; render(); },
 'revoke-grant': (b) => { delete s.grants[b.dataset.id]; delete s.keepLock[b.dataset.id]; log(`撤銷「${item(b.dataset.id).name}」的網站授權`); render(); },
 'extend-grant': (b) => extendDialog(b.dataset.id),
 'extend-confirm': (b) => {
  const m = readDuration(b.closest('.approve')); if(m === null) return;
  const id = b.dataset.id, cap = now() + MAX_GRANT * MIN, until = Math.min(s.grants[id] + m * MIN, cap);
  s.grants[id] = until; s.sessions.filter(x => x.itemId === id).forEach(x => x.expiresAt = until);
  log(`延長「${item(id).name}」的網站授權`, `到 ${hm(until)}`); closeModal(); render();
  note(until === cap ? `已達上限：從現在起最多 12 小時，授權到 ${hm(until)}。` : `已延長 ${fmtDur(m)}，授權到 ${hm(until)}。`);
 },
 'approve-once': (b) => decide(b.dataset.id, 'once'),
 'approve-site': (b) => { const m = readDuration(b.closest('.approve')); if(m !== null) decide(b.dataset.id, 'site', m, b.closest('.approve').querySelector('.keep-lock').checked); },
 'reject': (b) => decide(b.dataset.id, 'reject'),
 'mfa-done': (b) => { const x = s.sessions.find(z => z.id === b.dataset.id); if(!x) return; x.phase = 'logged_in'; log(`「${item(x.itemId).name}」登入完成`, 'logged_in'); render(); },
 'end-session': (b) => { const x = s.sessions.find(z => z.id === b.dataset.id); if(!x) return; s.sessions = s.sessions.filter(z => z !== x); log(`停止 ${x.client} 的 AI 工作`, '已停止'); render(); },
 'export': () => requireAuth('sensitive', {op:'export'}, true),
 'email-enable': () => requireAuth('sensitive', {op:'email-enable'}, true),
 'email-change': () => requireAuth('sensitive', {op:'email-change'}, true),
 'email-disable': () => requireAuth('sensitive', {op:'email-disable'}, true),
 'change-master': () => requireAuth('sensitive', {op:'change-master'}, true),
 'email-disable-confirm': () => { s.email = null; s.otp = null; log('停用 Email 驗證碼'); closeModal(); render(); },
 'import': importDialog,
 'import-confirm': () => {
  let added = 0;
  CSV_ROWS.forEach((r, k) => { const u = new URL(r.url); if(s.items.some(i => i.type === 'login' && i.origin === u.origin && i.account === r.account)) return; added++; s.items.push({id:'csv' + now() + k, type:'login', name:r.name, url:u.href, origin:u.origin, alias:r.account, account:r.account, password:'Demo-Only!Import2026', note:'', ai:false}); });
  s.dataVersion++; log('匯入 CSV', `新增 ${added} 筆，略過 ${CSV_ROWS.length - added} 筆`); closeModal(); render(); note(`已匯入 ${added} 筆。請刪除明文 CSV 檔。`);
 },
 'add-client': pairDialog,
 'pair-done': () => { const name = $('#client-name').value; s.clients.push({id:'c' + now(), name}); log(`配對 ${name}`); closeModal(); render(); },
 'revoke-client': (b) => { const c = s.clients.find(x => x.id === b.dataset.id); s.clients = s.clients.filter(x => x !== c); s.sessions = s.sessions.filter(x => x.clientId !== c.id); s.pending = s.pending.filter(r => r.clientId !== c.id); log(`撤銷 ${c.name} 的連線`, '相關工作已停止'); render(); }
};
document.addEventListener('click', e => {
 const b = e.target.closest('button'); if(!b || b.disabled) return;
 if(b.dataset.nav){ hideSecret(); s.tab = b.dataset.nav; render(); return; }
 if(b.dataset.filter){ s.filter = b.dataset.filter; render(); return; }
 if(b.dataset.lab) return lab(b.dataset.lab);
 actions[b.dataset.action]?.(b);
});
document.addEventListener('input', e => {
 if(e.target.classList.contains('dur-custom')){ const box = e.target.closest('.duration'); box.querySelector('.long-warn').hidden = +e.target.value <= 120; box.querySelector('.dur-error').textContent = ''; return; }
 if(e.target.id !== 'search') return;
 s.search = e.target.value; const pos = e.target.selectionStart; render();
 $('#search').focus(); try { $('#search').setSelectionRange(pos, pos); } catch {}
});
document.addEventListener('change', e => {
 if(e.target.id === 'show-pass') $('#item-pass').type = e.target.checked ? 'text' : 'password';
 if(e.target.classList.contains('dur')){
  const box = e.target.closest('.duration'), custom = e.target.value === 'custom';
  box.querySelector('.custom-dur').hidden = !custom;
  box.querySelector('.long-warn').hidden = (custom ? +box.querySelector('.dur-custom').value : +e.target.value) <= 120;
  box.querySelector('.dur-error').textContent = '';
 }
 if(e.target.id === 'idle'){ s.idle = +e.target.value; log(`閒置自動鎖定改為 ${s.idle} 分鐘`); }
});
document.addEventListener('submit', e => {
 e.preventDefault(); const f = e.target;
 if(f.id === 'master-form'){
  const p = $('#new-master').value, err = $('#master-error');
  if(p.length < 12) return err.textContent = '請設定至少 12 字元。';
  if(p !== $('#confirm-master').value) return err.textContent = '兩次輸入不一致。';
  s.master = p;
  if(f.dataset.mode === 'setup'){ s.screen = 'setup-email'; log('設定主密碼'); return render(); }
  closeModal(); log(f.dataset.mode === 'reset' ? '以 Email 驗證重設主密碼' : '變更主密碼'); note('主密碼已更新。舊備份仍以當時的備份密碼還原。'); render();
 }
 if(f.id === 'email-form'){
  const addr = $('#email-address');
  if(!addr.checkValidity()) return $('#email-error').textContent = '請輸入有效的信箱。';
  sendCode('bind', {addr:addr.value.trim(), ctx:f.dataset.context});
 }
 if(f.id === 'backup-form'){
  const p = $('#backup-pass').value, err = $('#backup-error');
  if(p.length < 12) return err.textContent = '請設定至少 12 字元。';
  if(p !== $('#backup-confirm').value) return err.textContent = '兩次輸入不一致。';
  s.backup = {version:s.dataVersion, count:s.items.length, date:stamp(), pass:p};
  log('匯出備份', `${s.items.length} 筆`);
  if(f.dataset.context === 'setup'){ s.screen = 'main'; s.fresh = now(); } else closeModal();
  note(`已建立演練備份 PASS_PW-demo.passpw（${s.items.length} 筆）。`); render();
 }
 if(f.id === 'unlock-form' && checkMaster($('#unlock-pass').value, $('#unlock-error'))) finishUnlock();
 if(f.id === 'verify-form' && checkMaster($('#verify-pass').value, $('#verify-error'))){ s.fresh = now(); complete(); }
 if(f.id === 'code-form'){
  const o = s.otp, err = $('#code-error');
  if(!o || now() >= o.expires){ if(o && o.mail.state === 'valid') o.mail.state = 'expired'; return err.textContent = '驗證碼已失效，請重新寄送。'; }
  if($('#code').value !== o.mail.code){
   o.attempts++;
   if(o.attempts < 5) return err.textContent = `驗證碼不正確，還可以再試 ${5 - o.attempts} 次。`;
   o.expires = 0; o.mail.state = 'void'; s.voided++; log('Email 驗證碼錯誤 5 次', '已作廢');
   if(s.voided >= 3){ s.voided = 0; s.pausedUntil = now() + 15 * MIN; s.otp = null; log('連續 3 組驗證碼作廢', 'Email 驗證暫停 15 分鐘'); return dialog('Email 驗證暫停 15 分鐘', `<p>連續 3 組驗證碼作廢，暫時不能用 Email 驗證。</p>${failActions(o.purpose)}`); }
   return codeDialog('已錯誤 5 次，這組驗證碼已作廢，請重新寄送。');
  }
  o.mail.state = 'used'; s.otp = null; s.voided = 0; log(`Email 驗證（${PURPOSES[o.purpose]}）`, '通過'); onCode(o);
 }
 if(f.id === 'item-form'){
  const type = f.dataset.type, old = item(f.dataset.id), err = $('#item-error'), v = (id) => $('#' + id)?.value.trim() ?? '';
  const it = {...(old || {id:'i' + now(), type}), name:v('item-name')};
  if(type === 'login'){
   let url; try { url = new URL(v('item-url')); } catch { return err.textContent = '請輸入完整網址，例如 https://example.com/login。'; }
   if(url.protocol !== 'https:' || url.username || url.password) return err.textContent = '只接受 HTTPS 網址，且網址不能包含帳號密碼。';
   url.hash = '';
   Object.assign(it, {url:url.href, origin:url.origin, alias:v('item-alias'), account:v('item-account'), note:v('item-note'), ai:$('#item-ai').checked, grantMin:+$('#item-grant').value, selectors:v('sel-user') || v('sel-pass') ? {user:v('sel-user'), pass:v('sel-pass')} : null});
  }
  if(type === 'password') Object.assign(it, {account:v('item-account'), note:v('item-note')});
  if(type === 'note'){ const c = $('#item-content').value; if(c) it.note = c; }
  else { const p = $('#item-pass').value; if(p) it.password = p; }
  // Changing where or as whom the AI logs in, or turning AI off, ends related AI work.
  if(old && type === 'login' && (old.origin !== it.origin || old.account !== it.account || old.password !== it.password || (old.ai && !it.ai))) stopItem(old.id, '項目已變更');
  s.items = old ? s.items.map(x => x.id === old.id ? it : x) : [...s.items, it];
  s.dataVersion++; closeModal(); s.tab = 'detail'; s.selected = it.id; log(`${old ? '更新' : '新增'}「${it.name}」`); render(); note('已儲存（假資料）。');
 }
 if(f.id === 'restore-form'){
  const p = $('#restore-pass').value;
  if(p !== 'DemoBackup!2026' && p !== s.backup?.pass) return $('#restore-error').textContent = '無法開啟備份：密碼錯誤或檔案損毀。目前密碼庫未更動。';
  const b = p === s.backup?.pass ? s.backup : {date:'10/01 09:00', count:5};
  dialog('備份檢查成功', `${kv('備份日期', b.date)}${kv('項目數', b.count + ' 筆')}<p>確認後會另建一個新密碼庫，目前的密碼庫保持不變。還原後需重新設定 Email 驗證碼與 AI 連線。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="restore-confirm">另建新密碼庫（演練）</button></div>`);
 }
});
window.addEventListener('blur', () => { if(s?.revealed){ hideSecret(); render(); } });
document.addEventListener('visibilitychange', () => { if(document.hidden && s?.revealed){ hideSecret(); render(); } });
$('#modal').addEventListener('cancel', () => { s.verifying = null; });
setInterval(expireTick, 5000);
reset();

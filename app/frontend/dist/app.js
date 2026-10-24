"use strict";
// Keyward management UI. All data and rules live in the Go core; this file only renders and asks.
const $ = (q) => document.querySelector(q);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api = () => window.go.main.App;
const TYPES = {login:'網站登入', password:'其它密碼', note:'安全備註'};
const DURATIONS = [30, 60, 120, 240, 480];
const LOCK_REASONS = {idle:'閒置時間到，已自動鎖定。', windows:'Windows 已鎖定，密碼庫一併鎖定。', sleep:'電腦曾休眠，密碼庫已鎖定。', manual:''};
const REVEAL_SECONDS = 30;
const fmtDur = (m) => UI_LANG === 'en' ? (m < 60 ? `${m} minutes` : m === 60 ? '1 hour' : `${m / 60} hours`) : (m < 60 ? `${m} 分鐘` : `${m / 60} 小時`);
const locale = () => UI_LANG === 'en' ? 'en-US' : 'zh-TW';

let st = {status:null, view:'vault', filter:'', search:'', items:[], selected:null, detail:null, revealed:null, revealUntil:0, lockReason:''};
let revealTimer, toastTimer, codeTimer, codeCtx = null, lastView = '';
const PURPOSE_LABEL = {unlock:'解鎖', reset:'重設主密碼', reveal:'顯示／複製密碼', sensitive:'確認敏感操作', bind:'確認信箱'};
const OP_LABEL = {'email-setup':'設定 Email 驗證碼', 'email-disable':'停用 Email 驗證碼', 'export':'匯出備份', 'master-reset':'不用舊密碼設定新主密碼'};
const email = () => st.status?.email || {};

// Errors from Go arrive as "code:message".
function parseErr(e){
 const s = String(e?.message ?? e ?? '');
 const i = s.indexOf(':');
 return i > 0 && /^[a-z_]+$/.test(s.slice(0, i)) ? {code:s.slice(0, i), msg:s.slice(i + 1)} : {code:'internal', msg:s || '發生未預期的錯誤。'};
}
function note(msg){ $('#toast').textContent = msg; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').textContent = '', 4500); }
function closeModal(){ const m = $('#modal'); if(m.open) m.close(); m.innerHTML = ''; clearInterval(codeTimer); }
function dialog(title, body){ const m = $('#modal'); m.innerHTML = `<h2 id="dialog-title">${title}</h2>${body}`; if(!m.open) m.showModal(); const f = m.querySelector('input,select,textarea'); if(f) f.focus(); }
function hideSecret(){ st.revealed = null; clearInterval(revealTimer); }
const kv = (k, v) => `<div class="keyvalue"><span>${k}</span>${esc(v)}</div>`;

// ---------- data ----------
async function refreshStatus(){ st.status = await api().Status(); }
async function loadItems(){ st.items = await api().List(st.search, st.filter); }
async function navTo(view, extra = {}){
 hideSecret(); Object.assign(st, {view}, extra);
 try {
  if(view === 'vault'){ await loadItems(); await refreshStatus(); }
  if(view === 'detail') st.detail = await api().Get(st.selected);
  if(view === 'settings') await refreshStatus();
  if(view === 'ai') await loadAI();
 } catch(e){ return handle(e); }
 render();
}
// handle shows errors; a locked vault sends the person to the lock screen.
async function handle(e, target){
 const {code, msg} = parseErr(e);
 if(code === 'locked'){ await toLocked(''); return; }
 if(target){ target.textContent = msg; return; }
 note(msg);
}
async function toLocked(reason){
 // A repeated lock notice (e.g. the event after a manual lock) must not close a dialog opened on the lock screen.
 const already = st.status?.locked;
 hideSecret(); if(!already) closeModal();
 if(!already || reason) st.lockReason = reason;
 await refreshStatus(); render();
}

// ---------- layout ----------
function shell(content){
 const on = st.status.initialized && !st.status.locked;
 const pending = st.ai?.pending?.length || 0;
 const nav = [['vault','密碼清單'],['ai','AI 代理' + (pending ? ` · ${pending}` : '')],['settings','設定']];
 return `<div class="shell"><aside><div class="logo">Keyward</div><div class="sublogo">個人密碼管理器</div><nav>${nav.map(([id,l]) => `<button data-nav="${id}" class="${on && (st.view === id || (id === 'vault' && st.view === 'detail')) ? 'active' : ''}" ${on ? '' : 'disabled'}>${l}</button>`).join('')}</nav><div class="aside-note">密碼只存在這台電腦<br>記得定期匯出備份</div></aside><main>${content}</main></div>`;
}
function header(title, sub){ return `<div class="top"><div><h1>${title}</h1><p class="muted">${sub}</p></div><div class="title-actions"><button data-action="lock">鎖定密碼庫</button><button class="danger" data-action="lock-all" title="鎖定並停止所有 AI 工作">全部鎖定並停止</button></div></div>`; }
function masterFields(label){ return `<label for="m1">${label}</label><input id="m1" type="password" autocomplete="off" required><label for="m2">再次輸入</label><input id="m2" type="password" autocomplete="off" required><p class="small muted">至少 8 個字元，並包含大寫英文字母與特殊符號（例如 ! @ # $）。Keyward 不會保存主密碼本身；忘記主密碼將無法解開資料。</p>`; }

function setupView(){
 return `<div class="intro"><h1>建立你的密碼庫</h1><p class="muted">主密碼是解開資料的唯一方式，請記住它。</p><div class="panel"><form id="setup-form">${masterFields('主密碼')}<div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button class="primary" type="submit">建立密碼庫</button></div></form></div><p class="small muted">資料存在這台電腦的使用者資料夾，內容全部加密。</p><div class="panel"><h2>換了電腦或重新安裝？</h2><p class="muted">用之前匯出的 Keyward 備份檔還原。</p><button data-action="restore">從備份還原</button></div></div>`;
}
function lockedView(){
 const why = LOCK_REASONS[st.lockReason];
 return `<div class="intro"><div class="lock-icon" aria-hidden="true">▣</div><h1>密碼庫已鎖定</h1>${why ? `<div class="banner reason">${why}</div>` : ''}<p class="muted">解鎖後 60 秒內，顯示或複製密碼不必再驗證一次。</p><div class="panel"><form id="unlock-form"><label for="unlock-pass">主密碼</label><input id="unlock-pass" type="password" autocomplete="off" required><div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="submit" class="primary">解鎖</button></div></form>${emailUnlock()}<div class="row wrap links">${email().enabled ? '<button class="text" data-action="email-reset">忘記主密碼？用 Email 驗證後重設</button>' : ''}<button class="text" data-action="restore">${email().enabled ? '換了電腦？從備份還原' : '忘記主密碼或換了電腦？從備份還原'}</button></div></div><p class="small muted links">已登入的 AI 工作可能仍在進行。<button class="text danger-text" data-action="ai-stop-all">停止所有 AI 工作</button></p></div>`;
}
function emailUnlock(){
 const e = email();
 if(!e.enabled) return '';
 const paused = e.pausedSeconds ? `<p class="small error">連續輸入錯誤，Email 驗證暫停中（約 ${Math.ceil(e.pausedSeconds / 60)} 分鐘後恢復），請改用主密碼。</p>` : '';
 return `<div class="divider"><span>或</span></div><button data-action="email-unlock" ${e.pausedSeconds ? 'disabled' : ''}>寄送 Email 驗證碼解鎖</button><p class="small muted">寄至 ${esc(e.masked)} · 10 分鐘內有效，只能使用一次</p>${paused}`;
}
function itemMeta(i){ return i.type === 'login' ? `${i.host} · ${i.alias}` : i.type === 'password' ? (i.account || '其它密碼') : '僅供本人查看'; }
const fmtDate = (unix) => new Date(unix * 1000).toLocaleString(locale(), {hour12:false, year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'});
function resetBanner(){
 const s = email().resetSeconds;
 if(!s) return '';
 return `<div class="banner warn">你已用 Email 驗證碼解鎖，還沒設定新主密碼（剩約 ${Math.ceil(s / 60)} 分鐘，不需要舊密碼）。<button class="text" data-action="reset-master">設定新主密碼</button></div>`;
}
function backupBanner(){
 const b = st.status.backup;
 if(!b.stale) return '';
 return `<div class="banner warn">${b.at ? `備份已過期：${fmtDate(b.at)} 之後有新增、修改或刪除。` : '還沒有備份。電腦故障或忘記主密碼時，沒有備份就找不回資料。'}<button class="text" data-action="export">匯出備份</button></div>`;
}
function vaultView(){
 const chips = [['','全部'], ...Object.entries(TYPES)].map(([k,l]) => `<button class="chip ${st.filter === k ? 'on' : ''}" aria-pressed="${st.filter === k}" data-filter="${k}">${l}</button>`).join('');
 const rows = st.items.map(i => `<article class="panel item"><div class="icon" aria-hidden="true">${esc([...i.name][0] || '?')}</div><div class="item-body"><h3>${esc(i.name)}</h3><div class="small muted">${esc(TYPES[i.type])} · ${esc(itemMeta(i))}</div></div><div class="item-actions">${i.type === 'login' && i.ai ? '<span class="pill blue">已設定允許 AI</span>' : ''}<button data-action="open" data-id="${esc(i.id)}">查看</button></div></article>`).join('');
 const empty = st.search || st.filter ? '<div class="panel empty"><h2>找不到符合的項目</h2><p class="muted">試試其他名稱、網址或帳號，或切換類型。</p><button data-action="clear-search">清除搜尋與篩選</button></div>' : '<div class="panel empty"><h2>還沒有任何項目</h2><p class="muted">新增第一筆網站帳密或其它密碼。</p><button class="primary" data-action="add">＋ 新增</button></div>';
 return `${header('密碼清單','網站帳密與其它密碼，加密保存在這台電腦。')}${resetBanner()}${backupBanner()}<div class="row between toolbar wrap"><input id="search" type="search" aria-label="搜尋名稱、網址或帳號" placeholder="搜尋名稱、網址或帳號" value="${esc(st.search)}"><button class="primary" data-action="add">＋ 新增</button></div><div class="chips" role="group" aria-label="類型篩選">${chips}</div><div class="items">${rows || empty}</div>`;
}
function detailView(){
 const d = st.detail, shown = st.revealed !== null;
 const label = d.type === 'note' ? '內容' : '密碼';
 const left = Math.max(0, Math.ceil((st.revealUntil - Date.now()) / 1000));
 const hint = shown ? `<span id="reveal-count">${left}</span> 秒後自動遮罩；切換畫面、視窗失焦或鎖定時立即遮罩。` : '最近 60 秒內驗證過可直接顯示，否則需要輸入主密碼。';
 const fields = d.type === 'login' ? kv('帳號別名', d.alias) + kv('帳號', d.account) : d.type === 'password' && d.account ? kv('帳號', d.account) : '';
 const side = d.type === 'login'
  ? `<h2>網站資訊</h2>${kv('登入網址', d.url)}${d.loginUrl ? kv('登入頁網址', d.loginUrl) : ''}${kv('AI 代理登入', d.ai ? `已設定允許（預設授權 ${fmtDur(d.grantMin || 30)}）` : '未開放')}<p class="small muted">開放後，已配對的 AI 工具可以要求登入這個網站；每次都由你在「AI 代理」頁核准，密碼由 Keyward 填入，不交給 AI。</p>`
  : `<h2>使用範圍</h2><p class="muted">${TYPES[d.type]}只供你本人查看。</p>`;
 return `${header(esc(d.name), esc(TYPES[d.type] + (d.host ? ' · ' + d.host : '')))}<button class="text" data-nav="vault">← 返回清單</button><div class="details-grid"><div class="panel"><h2>${d.type === 'note' ? '備註內容' : '帳號與密碼'}</h2>${fields}<label>${label}</label><div class="password-view ${d.type === 'note' ? 'note-view' : ''}">${shown ? esc(st.revealed) : '••••••••••••'}</div><p class="small muted">${hint}</p><div class="row wrap"><button data-action="${shown ? 'hide' : 'reveal'}">${shown ? '隱藏' : '顯示'}</button><button data-action="copy">複製</button></div>${d.type !== 'note' && d.note ? kv('備註', d.note) : ''}</div><div class="panel">${side}<div class="row wrap"><button data-action="edit">編輯</button><button class="danger" data-action="delete">刪除</button></div></div></div>`;
}
function settingsView(){
 const idle = st.status.idleMinutes, b = st.status.backup;
 const bk = b.at ? `${b.stale ? '備份已過期' : '備份為最新'} · ${fmtDate(b.at)} · ${b.count} 筆` : '尚未建立備份';
 return `${header('設定','主密碼、自動鎖定與備份。')}<div class="settings-grid"><div class="panel"><h2>本人驗證</h2>${langSetting()}<div class="keyvalue"><span>主密碼</span>已設定 ${email().resetSeconds ? '<button class="text" data-action="reset-master">設定新主密碼（不需舊密碼）</button>' : '<button class="text" data-action="change-master">變更主密碼</button>'}</div>${emailSetting()}<label for="idle">閒置自動鎖定</label><select id="idle">${[1,5,15,30].map(m => `<option value="${m}" ${idle === m ? 'selected' : ''}>${fmtDur(m)}</option>`).join('')}</select><p class="small muted">Windows 鎖定或電腦休眠時，密碼庫也會立即鎖定。變更信箱、停用 Email、匯出備份時都要重新驗證，不沿用解鎖後 60 秒內的免驗證。</p></div><div class="panel"><h2>備份與還原</h2><p><span class="pill ${b.stale ? 'warn' : 'good'}">${bk}</span></p><p class="small muted">備份檔以你設定的備份密碼加密，不依賴這台電腦，可以在別台電腦還原。請把備份檔存到另一個磁碟或隨身碟，並記住備份密碼。</p><div class="row wrap"><button class="primary" data-action="export">匯出備份</button><button data-action="restore">從備份還原</button></div></div><div class="panel"><h2>從瀏覽器匯入</h2><p class="muted">匯入 Chrome、Edge、Firefox 或 Bitwarden 匯出的密碼 CSV。匯入前會先列出預覽，重複的項目會略過。</p><button data-action="import">匯入 CSV…</button></div><div class="panel"><h2>AI 代理登入</h2><p class="muted">配對 AI 工具、核准登入要求與查看進行中的工作，都在「AI 代理」頁。</p><button data-nav="ai">前往 AI 代理</button></div></div>`;
}
function langSetting(){
 const p = langPref();
 const opt = (v, l) => `<option value="${v}" ${p === v ? 'selected' : ''}>${l}</option>`;
 return `<div class="keyvalue"><span>語言</span><select id="lang-select" aria-label="Language">${opt('auto', '自動（依 Windows 語言）')}${opt('zh-TW', '中文（繁體）')}${opt('en', 'English')}</select></div><p class="small muted">介面語言，自動時依 Windows 顯示語言決定；Email 驗證信也使用這個語言。</p>`;
}
document.addEventListener('change', (e) => { if(e.target.id === 'lang-select'){ setLangPref(e.target.value); render(); } });
function emailSetting(){
 const e = email();
 if(!e.available) return '<div class="keyvalue"><span>Email 驗證碼</span>這個版本不支援</div>';
 const row = e.enabled
  ? `已啟用 · ${esc(e.masked)} <button class="text" data-action="email-change">變更信箱</button><button class="text" data-action="email-disable">停用</button>`
  : '未啟用 <button class="text" data-action="email-enable">設定 Email 驗證碼</button>';
 return `<div class="keyvalue"><span>Email 驗證碼</span>${row}</div>${e.pausedSeconds ? '<p class="small error">連續輸入錯誤，Email 驗證暫停中，請改用主密碼。</p>' : ''}<p class="small muted">選配：解鎖、顯示密碼或忘記主密碼時，可改用寄到你信箱的 6 位數驗證碼。主密碼仍然必要。</p>`;
}
function render(){
 const s = st.status;
 const body = !s.initialized ? setupView() : s.locked ? lockedView() : ({detail:detailView, settings:settingsView, ai:aiView}[st.view] || vaultView)();
 $('#app').innerHTML = shell(body);
 const view = [s.initialized, s.locked, st.view, st.selected].join(':');
 if(view !== lastView){ window.scrollTo(0, 0); const f = $('#app form input'); if(f) f.focus(); }
 lastView = view;
}

// ---------- secrets ----------
function authDialog(act){
 dialog('確認是你本人', `<p>要${act === 'copy' ? '複製' : '顯示'}「${esc(st.detail.name)}」的${st.detail.type === 'note' ? '內容' : '密碼'}，請輸入主密碼。</p><form id="auth-form" data-act="${act}"><label for="auth-pass">主密碼</label><input id="auth-pass" type="password" autocomplete="off" required><div class="field-error" id="auth-error" role="alert"></div>${email().enabled ? '<button type="button" class="text" data-action="auth-email">改寄 Email 驗證碼</button>' : ''}<div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button class="primary" type="submit">驗證</button></div></form>`);
}
async function useSecret(act, master = ''){
 const id = st.selected;
 try {
  if(act === 'copy'){ await api().Copy(id, master); closeModal(); note('已複製，30 秒後清除剪貼簿。'); return; }
  const secret = await api().Reveal(id, master);
  closeModal(); showSecret(secret);
 } catch(e){
  const {code, msg} = parseErr(e);
  if(code === 'need_auth') return authDialog(act);
  handle(e, master ? $('#auth-error') : null);
 }
}
function showSecret(secret){
 hideSecret(); st.revealed = secret; st.revealUntil = Date.now() + REVEAL_SECONDS * 1000; render();
 revealTimer = setInterval(() => {
  const left = Math.ceil((st.revealUntil - Date.now()) / 1000);
  if(left <= 0){ hideSecret(); render(); return; }
  const el = $('#reveal-count'); if(el) el.textContent = left;
 }, 250);
}

// ---------- items ----------
async function editForm(type, d){
 type = d?.type || type;
 const pwLabel = d ? '替換密碼（留白保留原密碼）' : '密碼';
 const pw = `<label for="f-pass">${pwLabel}</label><div class="row pw-row"><input id="f-pass" type="password" autocomplete="new-password" ${d ? '' : 'required'}><button type="button" data-action="gen">產生密碼</button></div><label class="check"><input id="show-pass" type="checkbox">顯示輸入內容</label>`;
 let f = `<label for="f-name">名稱</label><input id="f-name" value="${esc(d?.name)}" required>`;
 if(type === 'login') f += `<label for="f-url">登入網址（HTTPS；本機開發可用 http://localhost）</label><input id="f-url" type="url" value="${esc(d?.url)}" placeholder="https://example.com/login" required><label for="f-login-url">登入頁網址（選填）</label><input id="f-login-url" type="url" value="${esc(d?.loginUrl)}" placeholder="https://sso.example.com"><p class="small muted">網站會跳到另一個網址登入時才需要填，例如學校或公司的單一登入（SSO）。Keyward 只在登入網址或這個網址填入密碼。</p><p class="small muted">http 只限這台電腦（localhost、127.0.0.1）的開發中網站；密碼會交給在那個連接埠上執行的程式，請確認是你自己的服務。</p><label for="f-alias">帳號別名</label><input id="f-alias" value="${esc(d?.alias)}" placeholder="例如：工作帳號" required><label for="f-account">帳號</label><input id="f-account" value="${esc(d?.account)}" autocomplete="off" required>${pw}<label for="f-note">備註</label><input id="f-note" value="${esc(d?.note)}"><details class="small"><summary>AI 代理登入</summary><label class="check"><input id="f-ai" type="checkbox" ${d?.ai ? 'checked' : ''}>允許已配對的 AI 提出登入要求</label><label for="f-grant">AI 預設授權時間</label><select id="f-grant">${DURATIONS.map(m => `<option value="${m}" ${m === (d?.grantMin || 30) ? 'selected' : ''}>${fmtDur(m)}</option>`).join('')}</select></details>`;
 if(type === 'password') f += `<label for="f-account">帳號或識別（選填）</label><input id="f-account" value="${esc(d?.account)}" autocomplete="off">${pw}<label for="f-note">備註</label><input id="f-note" value="${esc(d?.note)}">`;
 if(type === 'note') f += `<label for="f-content">${d ? '替換內容（留白保留原內容）' : '內容'}</label><textarea id="f-content" rows="6" ${d ? '' : 'required'}></textarea>`;
 dialog(`${d ? '編輯' : '新增'}${TYPES[type]}`, `<form id="item-form" data-id="${esc(d?.id || '')}" data-type="${type}">${f}<div class="field-error" id="item-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button type="submit" class="primary">儲存</button></div></form>`);
}

// ---------- backup, restore, CSV ----------
function exportDialog(viaEmail = false){
 const who = viaEmail ? '<p class="banner">已用 Email 驗證碼確認是你本人。</p>' : `<label for="ex-master">目前的主密碼</label><input id="ex-master" type="password" autocomplete="off" required>${email().enabled ? '<button type="button" class="text" data-action="export-email">改寄 Email 驗證碼確認本人</button>' : ''}`;
 dialog('匯出加密備份', `<form id="export-form">${who}<label for="ex-pass">備份密碼</label><input id="ex-pass" type="password" autocomplete="off" required><label for="ex-confirm">再次輸入備份密碼</label><input id="ex-confirm" type="password" autocomplete="off" required><p class="small muted">規則與主密碼相同（至少 8 個字元，含大寫英文字母與特殊符號），也可以直接用主密碼。還原時只需要備份檔與備份密碼，忘記它就無法還原。驗證通過後會詢問存檔位置；寫入後會立即讀回確認可以還原。</p><div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button class="primary" type="submit">選擇位置並匯出</button></div></form>`);
}
function restoreDialog(file = ''){
 const keep = st.status.initialized ? '<p class="small muted">目前的密碼庫不會被覆寫：它的檔案會改名保留在同一個資料夾，之後仍可用原本的主密碼開啟。</p>' : '';
 dialog('從備份還原', `<p>選擇 Keyward 備份檔（.keyward；舊版 PASS_PW 的 .passpw 也可以），輸入匯出時設定的備份密碼。</p><div class="row wrap"><button type="button" data-action="pick-backup">${file ? '換一個檔案…' : '選擇備份檔…'}</button><span class="muted">${esc(file)}</span></div>${keep}${file ? `<form id="restore-check-form"><label for="rs-pass">備份密碼</label><input id="rs-pass" type="password" autocomplete="off" required><div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-restore">取消</button><button class="primary" type="submit">檢查備份</button></div></form>` : '<div class="form-actions"><button type="button" data-action="cancel-restore">取消</button></div>'}`);
}
function restoreConfirmDialog(info){
 const parts = [`網站登入 ${info.logins}`, `其它密碼 ${info.passwords}`, `安全備註 ${info.notes}`].join('、');
 dialog('備份檢查成功', `${kv('備份時間', fmtDate(info.created))}${kv('項目', `${info.count} 筆（${parts}）`)}<p>還原後會建立新的密碼庫，請設定它的主密碼（可以與以前相同）。</p>${st.status.initialized ? '<p class="small muted">目前的密碼庫會改名保留，不會被覆寫或刪除。</p>' : ''}<form id="restore-form">${masterFields('新密碼庫的主密碼')}<div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-restore">取消</button><button class="primary" type="submit">還原為新的密碼庫</button></div></form>`);
}
const ACTION_LABEL = {login:'新增', password:'改存為其它密碼（非 HTTPS）', duplicate:'已存在，略過', skip:'沒有密碼，略過'};
function csvDialog(p){
 const shown = p.rows.slice(0, 200);
 dialog('匯入 CSV', `<p>${esc(p.file)}：${p.rows.length} 列。</p><p class="small muted">新增 ${p.new} 筆（其中 ${p.asPassword} 筆網址不是 HTTPS，改存為其它密碼）、重複略過 ${p.duplicate} 筆、沒有密碼略過 ${p.skipped} 筆。預覽不顯示密碼。</p><div class="table-wrap"><table class="preview"><thead><tr><th>名稱</th><th>網站</th><th>帳號</th><th>處理</th></tr></thead><tbody>${shown.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(r.host)}</td><td>${esc(r.account)}</td><td>${ACTION_LABEL[r.action]}</td></tr>`).join('')}</tbody></table></div>${p.rows.length > shown.length ? `<p class="small muted">只列出前 ${shown.length} 列。</p>` : ''}<div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="import-confirm" ${p.new ? '' : 'disabled'}>${p.new ? `匯入 ${p.new} 筆` : '沒有可匯入的項目'}</button></div>`);
}

// ---------- email codes ----------
// ctx: {title, purpose, send() -> CodeSent, verify(code), done(), master() to switch to the master password, cancel(), onSendError(msg)}
async function startCode(ctx){
 codeCtx = ctx;
 try { codeDialog(await ctx.send()); }
 catch(e){
  const {code, msg} = parseErr(e);
  if(code === 'locked') return handle(e);
  if($('#code-form')){ $('#code-form .field-error').textContent = msg; return; } // e.g. resend limit: keep the current code usable
  if(ctx.onSendError) return ctx.onSendError(msg);
  failDialog(msg);
 }
}
function failDialog(msg){
 const c = codeCtx;
 dialog('無法使用 Email 驗證碼', `<p class="error" role="alert">${esc(msg)}</p><div class="form-actions"><button data-action="code-cancel">關閉</button>${c?.master ? '<button class="primary" data-action="code-master">改用主密碼</button>' : ''}</div>`);
}
function codeDialog(sent, msg = ''){
 const c = codeCtx;
 c.resendAt = Date.now() + sent.resendIn * 1000;
 dialog(c.title, `<p>已寄到 <strong>${esc(sent.masked)}</strong>（${PURPOSE_LABEL[c.purpose]}）。</p><p class="small muted">${Math.round(sent.expiresIn / 60)} 分鐘內有效，只能使用一次；重新寄送後舊碼立即失效。沒收到請看垃圾郵件匣。</p><form id="code-form"><label for="code">6 位數驗證碼</label><input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><div class="field-error" id="form-error" role="alert">${esc(msg)}</div><div class="row wrap"><button type="button" id="resend" data-action="code-resend" disabled>重新寄送</button>${c.master ? '<button type="button" class="text" data-action="code-master">改用主密碼</button>' : ''}</div><div class="form-actions"><button type="button" data-action="code-cancel">取消</button><button type="submit" class="primary">驗證</button></div></form>`);
 const tick = () => {
  const b = $('#resend'); if(!b){ clearInterval(codeTimer); return; }
  const left = Math.ceil((c.resendAt - Date.now()) / 1000);
  b.disabled = left > 0; b.textContent = left > 0 ? `重新寄送（${left} 秒）` : '重新寄送';
 };
 clearInterval(codeTimer); tick(); codeTimer = setInterval(tick, 500);
}
async function submitCode(){
 const c = codeCtx, err = $('#code-form .field-error');
 try { await c.verify($('#code').value.trim()); }
 catch(e){
  const {code} = parseErr(e);
  if(code === 'email_paused') return failDialog(parseErr(e).msg);
  if(code === 'code_gone') $('#code').value = '';
  return handle(e, err);
 }
 codeCtx = null; closeModal(); await c.done();
}
// endCode closes the code dialog; on the lock screen it also refreshes the Email pause notice.
async function endCode(){
 codeCtx = null; closeModal();
 if(st.status?.locked){ await refreshStatus(); render(); }
}
function sensitiveDialog(op, then){
 const viaEmail = email().enabled ? '<button type="button" class="text" data-action="sens-email">改寄 Email 驗證碼</button>' : '';
 st.afterSensitive = then;
 dialog('確認是你本人', `<p>要${OP_LABEL[op]}，請重新驗證。這個操作不沿用 60 秒內的免驗證。</p><form id="sens-form" data-op="${op}"><label for="sens-pass">主密碼</label><input id="sens-pass" type="password" autocomplete="off" required><div class="field-error" id="form-error" role="alert"></div>${viaEmail}<div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button class="primary" type="submit">驗證</button></div></form>`);
}
function sensitiveByEmail(op, then){
 startCode({title:'輸入 Email 驗證碼', purpose:'sensitive', send:() => api().SendCode('sensitive', op), verify:(c) => api().VerifyCode('sensitive', op, c), done:then, master:() => sensitiveDialog(op, then)});
}
async function emailForm(){
 let cur = {};
 try { cur = await api().EmailSettings(); } catch(e){ return handle(e); }
 const changing = email().enabled;
 dialog(changing ? '變更 Email 驗證碼設定' : '設定 Email 驗證碼', `<div class="banner warn">若 AI 工具能讀取這個信箱，請不要啟用 Email 驗證，改只用主密碼。</div><form id="email-form"><fieldset><legend>寄信設定（你自己的郵件帳號）</legend><div class="grid2"><div><label for="smtp-host">SMTP 伺服器</label><input id="smtp-host" value="${esc(cur.host)}" placeholder="smtp.gmail.com" autocomplete="off" required></div><div><label for="smtp-port">連接埠</label><select id="smtp-port"><option value="587" ${cur.port !== 465 ? 'selected' : ''}>587（STARTTLS）</option><option value="465" ${cur.port === 465 ? 'selected' : ''}>465（TLS）</option></select></div></div><label for="smtp-user">寄件帳號</label><input id="smtp-user" value="${esc(cur.user)}" placeholder="you@gmail.com" autocomplete="off" required><label for="smtp-pass">應用程式密碼${changing ? '（留白沿用目前的）' : ''}</label><input id="smtp-pass" type="password" autocomplete="off" ${changing ? '' : 'required'}><p class="small muted">請用郵件服務提供的「應用程式密碼」，不要用信箱的登入密碼。連線一律加密（TLS）。</p></fieldset><label for="email-to">收取驗證碼的信箱</label><input id="email-to" type="email" value="${esc(cur.to)}" autocomplete="off" required><details class="small"><summary>啟用後的安全取捨（請先閱讀）</summary><p>為了在鎖定時也能用驗證碼解鎖，資料金鑰會另外由 Windows 以你目前的使用者帳號保護一份，寄信設定也以同樣方式保存。這表示：同一個 Windows 帳號下執行的程式（包括能執行指令的 AI 工具）有機會不經驗證碼就解開資料。驗證碼是 Keyward 的放行規則，不是加密金鑰。在意這點請只用主密碼。</p><p>換電腦、重灌或換 Windows 帳號後，Email 驗證碼會無法使用，請改用主密碼。</p></details><div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="email-form-cancel">取消</button><button class="primary" type="submit">寄送測試驗證碼</button></div></form>`);
}
function resetDialog(viaCode){
 dialog('設定新主密碼', `<p>${viaCode ? '已通過 Email 驗證。請設定新的主密碼' : '已用 Email 驗證碼解鎖。請在 10 分鐘內設定新的主密碼'}；設定後舊主密碼不能再解鎖。</p><form id="reset-form">${masterFields('新主密碼')}<div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="reset-later">稍後再說</button><button class="primary" type="submit">更新主密碼</button></div></form>`);
}

// ---------- events ----------
const actions = {
 'reset-master': () => resetDialog(),
 'master-by-email': () => sensitiveByEmail('master-reset', () => resetDialog(true)),
 'reset-later': async () => { closeModal(); await refreshStatus(); render(); note('可在清單上方或設定頁繼續設定新主密碼。'); },
 'email-unlock': () => startCode({title:'用 Email 驗證碼解鎖', purpose:'unlock', send:() => api().SendCode('unlock', ''), verify:(c) => api().UnlockWithCode(c, false),
  done: async () => { st.lockReason = ''; await refreshStatus(); navTo('vault'); }, master: () => { closeModal(); $('#unlock-pass')?.focus(); }}),
 'email-reset': () => startCode({title:'忘記主密碼', purpose:'reset', send:() => api().SendCode('reset', ''), verify:(c) => api().UnlockWithCode(c, true),
  done: async () => { st.lockReason = ''; await refreshStatus(); await navTo('vault'); resetDialog(); }}),
 'auth-email': () => { const id = st.selected, act = $('#auth-form')?.dataset.act || 'show'; startCode({title:'輸入 Email 驗證碼', purpose:'reveal', send:() => api().SendCode('reveal', id), verify:(c) => api().VerifyCode('reveal', id, c), done:() => useSecret(act), master:() => authDialog(act)}); },
 'code-resend': () => startCode(codeCtx),
 'code-master': async () => { const c = codeCtx; await endCode(); c?.master?.(); },
 'code-cancel': async () => { const c = codeCtx; await endCode(); c?.cancel?.(); },
 'sens-email': () => sensitiveByEmail($('#sens-form').dataset.op, st.afterSensitive),
 'export-email': () => sensitiveByEmail('export', () => exportDialog(true)),
 'email-enable': () => sensitiveDialog('email-setup', emailForm),
 'email-change': () => sensitiveDialog('email-setup', emailForm),
 'email-disable': () => sensitiveDialog('email-disable', () => dialog('停用 Email 驗證碼？', '<p>停用後會刪除 Email 解鎖用的資料與寄信設定，待驗證的驗證碼也會作廢。之後只能用主密碼。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="danger" data-action="email-disable-confirm">停用</button></div>')),
 'email-disable-confirm': async () => { try { await api().DisableEmail(); closeModal(); await navTo('settings'); note('已停用 Email 驗證碼。'); } catch(e){ closeModal(); handle(e); } },
 'email-form-cancel': async () => { await api().CancelEmailSetup(); closeModal(); },
 'export': () => exportDialog(),
 'restore': () => restoreDialog(),
 'pick-backup': async () => { const name = await api().PickBackupFile(); if(name) restoreDialog(name); },
 'cancel-restore': async () => { await api().CancelRestore(); closeModal(); },
 'import': async () => { try { const p = await api().PickCSV(); if(p.file) csvDialog(p); } catch(e){ handle(e); } },
 'import-confirm': async (b) => {
  b.disabled = true;
  try {
   const r = await api().ImportCSV();
   await navTo('vault');
   dialog('匯入完成', `<p>已匯入 ${r.added} 筆${r.failed ? `，${r.failed} 筆格式不符未匯入` : ''}。</p><div class="banner warn">CSV 檔是明文，任何能讀檔的程式都看得到密碼。建議現在刪除，並清空資源回收筒。</div><div class="form-actions"><button data-action="cancel-modal">保留檔案</button><button class="danger" data-action="delete-csv">刪除這個 CSV 檔</button></div>`);
  } catch(e){ closeModal(); handle(e); }
 },
 'delete-csv': async () => { try { await api().DeleteImportedCSV(); closeModal(); note('已刪除 CSV 檔。'); } catch(e){ closeModal(); handle(e); } },
 'lock': async () => { await api().Lock(); await toLocked(''); },
 'cancel-modal': () => closeModal(),
 'open': (b) => navTo('detail', {selected:b.dataset.id}),
 'add': () => dialog('要新增什麼？', `<div class="type-choice">${Object.entries(TYPES).map(([k,l]) => `<button data-action="new-type" data-type="${k}">${l}<br><small>${k === 'login' ? '網站的帳號與密碼' : k === 'password' ? 'Wi-Fi、軟體授權、裝置 PIN 等' : '復原碼等需要保密的文字'}</small></button>`).join('')}</div><div class="form-actions"><button data-action="cancel-modal">取消</button></div>`),
 'new-type': (b) => editForm(b.dataset.type),
 'edit': () => { hideSecret(); render(); editForm(null, st.detail); },
 'delete': () => dialog('刪除這個項目？', `<p>刪除「${esc(st.detail.name)}」後無法復原。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="danger" data-action="delete-confirm">刪除</button></div>`),
 'delete-confirm': async () => { try { await api().Delete(st.selected); closeModal(); note('已刪除。'); navTo('vault'); } catch(e){ closeModal(); handle(e); } },
 'reveal': () => useSecret('show'),
 'copy': () => useSecret('copy'),
 'hide': () => { hideSecret(); render(); },
 'gen': async () => { const p = $('#f-pass'); p.value = await api().Generate(20, true); p.type = 'text'; $('#show-pass').checked = true; },
 'clear-search': () => navTo('vault', {search:'', filter:''}),
 'change-master': () => dialog('變更主密碼', `<form id="change-form"><label for="cur">目前的主密碼</label><input id="cur" type="password" autocomplete="off" required>${email().enabled ? '<button type="button" class="text" data-action="master-by-email">忘記目前的主密碼？改寄 Email 驗證碼</button>' : ''}${masterFields('新主密碼')}<div class="field-error" id="form-error" role="alert"></div><div class="form-actions"><button type="button" data-action="cancel-modal">取消</button><button class="primary" type="submit">更新主密碼</button></div></form>`)
};
document.addEventListener('click', e => {
 const b = e.target.closest('button'); if(!b || b.disabled) return;
 if(b.dataset.nav) return navTo(b.dataset.nav);
 if(b.dataset.filter !== undefined) return navTo('vault', {filter:b.dataset.filter});
 actions[b.dataset.action]?.(b);
});
let searchTimer;
document.addEventListener('input', e => {
 if(e.target.id !== 'search') return;
 st.search = e.target.value;
 clearTimeout(searchTimer);
 searchTimer = setTimeout(async () => {
  const pos = $('#search')?.selectionStart;
  try { await loadItems(); } catch(err){ return handle(err); }
  render(); const s = $('#search'); if(s){ s.focus(); try { s.setSelectionRange(pos, pos); } catch {} }
 }, 120);
});
document.addEventListener('change', async e => {
 if(e.target.id === 'show-pass') $('#f-pass').type = e.target.checked ? 'text' : 'password';
 if(e.target.id === 'idle'){ try { await api().SetIdleMinutes(+e.target.value); note(`閒置 ${e.target.value} 分鐘後自動鎖定。`); } catch(err){ handle(err); } }
});
document.addEventListener('submit', async e => {
 e.preventDefault(); const f = e.target, err = f.querySelector('.field-error');
 const btn = f.querySelector('[type=submit]'); btn.disabled = true;
 try {
  if(await aiSubmit(f)) return;
  if(f.id === 'setup-form'){ await api().Setup($('#m1').value, $('#m2').value); await refreshStatus(); return navTo('vault'); }
  if(f.id === 'unlock-form'){ await api().Unlock($('#unlock-pass').value); st.lockReason = ''; await refreshStatus(); return navTo('vault'); }
  if(f.id === 'auth-form'){ return await useSecret(f.dataset.act, $('#auth-pass').value); }
  if(f.id === 'code-form') return await submitCode();
  if(f.id === 'sens-form'){ await api().Authorize(f.dataset.op, $('#sens-pass').value); const then = st.afterSensitive; closeModal(); return then(); }
  if(f.id === 'reset-form'){ await api().ResetMaster($('#m1').value, $('#m2').value); closeModal(); await refreshStatus(); render(); return note('主密碼已更新，舊主密碼不能再解鎖。'); }
  if(f.id === 'email-form'){
   const input = {host:$('#smtp-host').value, port:+$('#smtp-port').value, user:$('#smtp-user').value, password:$('#smtp-pass').value, to:$('#email-to').value};
   return await startCode({title:'輸入測試驗證碼', purpose:'bind', send:() => api().StartEmailSetup(input), verify:(c) => api().FinishEmailSetup(c),
    done: async () => { await navTo('settings'); note(`Email 驗證碼已啟用：${email().masked}`); }, cancel:() => api().CancelEmailSetup(),
    onSendError:(msg) => { const e = $('#email-form .field-error'); if(e) e.textContent = msg; else failDialog(msg); }});
  }
  if(f.id === 'export-form'){
   const r = await api().ExportBackup($('#ex-master')?.value ?? '', $('#ex-pass').value, $('#ex-confirm').value);
   if(r.cancelled){ closeModal(); return note('已取消匯出。'); }
   await navTo(st.view);
   dialog('備份完成', `<p>已寫入並讀回確認：${r.info.count} 筆。</p>${kv('檔案位置', r.path)}<p class="small muted">請把這個檔案另外存到隨身碟或其它磁碟；只存在同一台電腦，電腦故障時會一起遺失。</p><div class="form-actions"><button class="primary" data-action="cancel-modal">知道了</button></div>`);
   return;
  }
  if(f.id === 'restore-check-form'){ const info = await api().PreviewRestore($('#rs-pass').value); return restoreConfirmDialog(info); }
  if(f.id === 'restore-form'){
   const r = await api().Restore($('#m1').value, $('#m2').value);
   st.lockReason = ''; closeModal(); await navTo('vault', {search:'', filter:''});
   dialog('還原完成', `<p>已從備份還原 ${r.count} 筆，並以新的主密碼建立密碼庫。</p>${r.keptAs ? kv('原本的密碼庫已保留為', r.keptAs) : ''}<div class="form-actions"><button class="primary" data-action="cancel-modal">知道了</button></div>`);
   return;
  }
  if(f.id === 'change-form'){ await api().ChangeMaster($('#cur').value, $('#m1').value, $('#m2').value); closeModal(); return note('主密碼已更新。'); }
  if(f.id === 'item-form'){
   const v = (id) => $('#' + id)?.value ?? '';
   const input = {id:f.dataset.id, type:f.dataset.type, name:v('f-name'), url:v('f-url'), loginUrl:v('f-login-url'), alias:v('f-alias'), account:v('f-account'), password:v('f-pass'), note:f.dataset.type === 'note' ? v('f-content') : v('f-note'), ai:!!$('#f-ai')?.checked, grantMin:+(v('f-grant') || 0)};
   const d = await api().Save(input);
   closeModal(); note('已儲存。'); return navTo('detail', {selected:d.id});
  }
 } catch(ex){ await handle(ex, err); }
 finally { if(btn.isConnected) btn.disabled = false; }
});

// Hide revealed secrets whenever the window loses focus or is hidden.
window.addEventListener('blur', () => { if(st.revealed !== null){ hideSecret(); render(); } });
document.addEventListener('visibilitychange', () => { if(document.hidden && st.revealed !== null){ hideSecret(); render(); } });

// Report the person's activity so idle lock counts only real use (throttled).
let lastTouch = 0;
for(const ev of ['mousemove','mousedown','keydown','wheel']) document.addEventListener(ev, () => {
 const now = Date.now();
 if(now - lastTouch > 10000 && st.status?.initialized && !st.status.locked){ lastTouch = now; api().Touch(); }
}, {passive:true});

async function boot(){
 applyLang(langPref());
 await refreshStatus();
 window.runtime.EventsOn('locked', (reason) => toLocked(reason));
 window.runtime.EventsOn('ai', (kind) => aiEvent(kind));
 if(st.status.initialized && !st.status.locked) return navTo('vault');
 render();
}
window.addEventListener('DOMContentLoaded', boot);

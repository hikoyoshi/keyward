"use strict";
// AI agent page: approvals, running work, site grants and paired AI tools. Uses helpers from app.js.
const AI_PHASE = {logging_in:'Keyward 正在填入帳密並登入', needs_user:'需要你在 Keyward 的 Chrome 視窗完成網站驗證', logged_in:'已登入，AI 工作中'};
const AI_TOOLS = ['Claude Code', 'Codex', 'OpenCode', 'Hermes Agent'];
const MAX_GRANT = 720;

async function loadAI(){ st.ai = await api().AIOverview(); }
const hm = (unix) => {
 const d = new Date(unix * 1000);
 return (d.toDateString() === new Date().toDateString() ? '' : UI_LANG === 'en' ? 'tomorrow ' : '明天 ') + d.toLocaleTimeString(locale(), {hour12:false, hour:'2-digit', minute:'2-digit'});
};

function durationPicker(selected, key){
 const preset = DURATIONS.includes(selected);
 return `<div class="duration"><label for="dur-${key}">授權時間</label><select id="dur-${key}" class="dur">${DURATIONS.map(m => `<option value="${m}" ${m === selected ? 'selected' : ''}>${fmtDur(m)}</option>`).join('')}<option value="custom" ${preset ? '' : 'selected'}>自訂…</option></select><div class="custom-dur" ${preset ? 'hidden' : ''}><label for="custom-${key}">自訂分鐘數（15–${MAX_GRANT}）</label><input id="custom-${key}" class="dur-custom" type="number" min="15" max="${MAX_GRANT}" step="15" value="${preset ? 90 : selected}"></div><p class="small long-warn" ${selected > 120 ? '' : 'hidden'}>長時間授權期間，AI 可持續操作此帳號；建議用於測試帳號或開發環境。</p><div class="field-error dur-error" role="alert"></div></div>`;
}
function readDuration(box){
 const sel = box.querySelector('.dur');
 const m = sel.value === 'custom' ? Math.round(+box.querySelector('.dur-custom').value) : +sel.value;
 if(!(m >= 15 && m <= MAX_GRANT)){ box.querySelector('.dur-error').textContent = `請輸入 15 到 ${MAX_GRANT} 分鐘。`; return null; }
 return m;
}

function requestInfo(r){
 const row = (k, v) => `<dt>${k}</dt><dd>${esc(v)}</dd>`;
 return `<dl class="ai-info">${row('AI 工具', r.client)}${row('網站', r.name)}${row('帳號', r.alias)}${row('網址', r.site)}</dl><p class="small muted">Keyward 會在自己的 Chrome 視窗填入帳密，AI 拿不到密碼。約 ${Math.max(0, r.left)} 秒內未回應會自動拒絕。</p>`;
}
function approveBox(r, where){
 const m = r.grantMin || 30;
 return `<div class="approve"><fieldset><legend>「允許此網站」的設定</legend><p class="small muted">期間內再要求登入這個網站不必重新核准，可隨時延長或撤銷。</p>${durationPicker(m, where + r.id)}<label class="check"><input type="checkbox" class="keep-win">Windows 鎖定時保留這個網站的 AI 工作</label><label class="check"><input type="checkbox" class="pause-idle">授權期間暫停閒置自動鎖定</label><details class="small muted"><summary>這兩個選項的影響</summary><p>Windows 鎖定時保留：只保留已登入的工作，鎖定期間仍不能填入帳密；你離開座位時 AI 仍在操作此帳號。</p><p>暫停閒置自動鎖定：有已登入的 AI 工作時密碼庫保持解鎖，網站登出時 AI 可以重新登入；這段期間能操作這台電腦的人也能直接打開密碼庫。</p></details></fieldset><div class="form-actions wrap approve-actions"><button data-action="ai-deny" data-id="${esc(r.id)}">拒絕</button><button data-action="ai-approve-once" data-id="${esc(r.id)}">允許這次（15 分鐘）</button><button class="primary" data-action="ai-approve-site" data-id="${esc(r.id)}">允許此網站<span class="site-dur">（${fmtDur(m)}）</span></button></div></div>`;
}
function approvalDialog(r){
 dialog('AI 登入要求', `<p><strong>${esc(r.client)}</strong> 想登入：</p>${requestInfo(r)}${approveBox(r, 'm')}`);
}

function aiView(){
 const o = st.ai || {pending:[], sessions:[], grants:[], clients:[], log:[]};
 const flags = (x) => `${x.keepOnWin ? ' · Windows 鎖定時保留' : ''}${x.pauseIdle ? ' · 暫停閒置鎖定' : ''}`;
 const warn = (o.browser ? '' : '<div class="banner warn">找不到 Google Chrome。AI 代理登入由 Keyward 控制自己的 Chrome 視窗，請先安裝 Chrome。</div>')
  + (o.pausesIdle ? '<div class="banner">有勾選「暫停閒置自動鎖定」的 AI 工作進行中，密碼庫不會因閒置而鎖定。</div>' : '');
 const pending = o.pending.map(r => `<div class="panel request"><span class="pill warn">等待你的核准</span><h2>${esc(r.client)} 想登入「${esc(r.name)}」</h2>${requestInfo(r)}${approveBox(r, 't')}</div>`).join('') || '<div class="panel empty">目前沒有待核准的登入要求。</div>';
 const sessions = o.sessions.map(x => `<div class="panel"><div class="row between wrap"><div><h3>${esc(x.name)} · ${esc(x.client)}</h3><p class="muted">${esc(x.note || AI_PHASE[x.phase] || x.phase)} · 到 ${hm(x.expires)}${flags(x)}</p></div><div class="row wrap">${x.phase === 'needs_user' ? `<button class="primary" data-action="ai-user-done" data-id="${esc(x.id)}">我已完成網站驗證</button>` : ''}<button class="danger" data-action="ai-stop" data-id="${esc(x.id)}">停止</button></div></div></div>`).join('') || '<div class="panel empty">目前沒有 AI 工作。</div>';
 const grants = o.grants.length ? `<h2>網站授權</h2><div class="panel">${o.grants.map(g => `<div class="row between wrap client"><div><strong>${esc(g.name)}</strong> · ${esc(g.client)}<div class="small muted">授權到 ${hm(g.until)}${flags(g)}</div></div><div class="row wrap"><button data-action="ai-extend" data-key="${esc(g.key)}">延長</button><button class="danger" data-action="ai-revoke-grant" data-key="${esc(g.key)}">撤銷</button></div></div>`).join('')}</div>` : '';
 const clients = o.clients.map(c => `<div class="row between wrap client"><div><strong>${esc(c.name)}</strong><div class="small muted">配對於 ${new Date(c.created * 1000).toLocaleDateString(locale())} · 與 Keyward 同一 Windows 帳號（未隔離）</div></div><button class="danger" data-action="ai-revoke-client" data-id="${esc(c.id)}" data-name="${esc(c.name)}">撤銷</button></div>`).join('') || '<p class="muted">尚未配對任何 AI 工具。</p>';
 const log = (o.log || []).slice(0, 60).map(l => `<div class="activity"><span>${new Date(l.time * 1000).toLocaleTimeString(locale(), {hour12:false})}</span><span>${esc([l.client, l.site].filter(Boolean).join(' · '))} <span>${esc(l.action)}</span></span><span>${esc(l.result)}</span></div>`).join('') || '<p class="muted">目前沒有紀錄。</p>';
 return `${header('AI 代理登入', 'AI 提出要求、由你核准；帳密由 Keyward 填進它自己的 Chrome，不交給 AI。')}${warn}<div class="stack"><h2>待核准要求</h2>${pending}<h2>進行中的 AI 工作</h2>${sessions}${grants}<h2>AI 連線</h2><div class="panel">${clients}<p class="small muted">「未隔離」表示同一 Windows 帳號下、能執行指令的 AI 理論上可以攻擊 Keyward 程序；Keyward 保證的是密碼不經由工具進入 AI 對話。</p><button class="primary" data-action="ai-add-client">新增 AI 連線</button></div><h2>活動紀錄（本次開啟後）</h2><div class="panel">${log}</div></div>`;
}

// Re-render the AI page, but never while the person is filling in an approval on it.
async function aiRefresh(){
 if(!st.status?.initialized || st.status.locked) return;
 try { await loadAI(); } catch(e){ return; }
 const busy = document.activeElement && document.activeElement.closest && document.activeElement.closest('#app .approve');
 if(st.view === 'ai' && !busy) render();
 else if(st.view !== 'ai') { const n = document.querySelector('[data-nav="ai"]'); const p = st.ai.pending.length; if(n) n.textContent = 'AI 代理' + (p ? ` · ${p}` : ''); }
}

async function aiEvent(kind){
 if(!st.status?.initialized || st.status.locked) return;
 await aiRefresh();
 const m = $('#modal');
 if(kind === 'request' && !m.open && st.ai?.pending?.length) approvalDialog(st.ai.pending[0]);
}
setInterval(aiRefresh, 5000); // countdowns and timeouts

async function afterAIAction(msg){
 closeModal();
 if(msg) note(msg);
 try { await loadAI(); } catch(e){ return handle(e); }
 if(st.view === 'ai') render(); else aiRefresh();
}
function legacyCopy(text){
 const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
 document.body.append(t); t.select(); const ok = document.execCommand('copy'); t.remove(); return ok;
}

Object.assign(actions, {
 'lock-all': async () => { await api().LockAll(); await toLocked(''); note('已鎖定並停止所有 AI 工作。'); },
 'ai-stop-all': async () => { await api().LockAll(); note('已停止所有 AI 工作。'); },
 'ai-approve-once': async (b) => { try { await api().AIApprove(b.dataset.id, {mode:'once'}); afterAIAction('已核准這次登入（15 分鐘）。'); } catch(e){ closeModal(); handle(e); } },
 'ai-approve-site': async (b) => {
  const box = b.closest('.approve'), m = readDuration(box);
  if(m === null) return;
  try {
   await api().AIApprove(b.dataset.id, {mode:'site', minutes:m, keepOnWinLock:box.querySelector('.keep-win').checked, pauseIdle:box.querySelector('.pause-idle').checked});
   afterAIAction(`已允許此網站 ${fmtDur(m)}。`);
  } catch(e){ closeModal(); handle(e); }
 },
 'ai-deny': async (b) => { try { await api().AIDeny(b.dataset.id); afterAIAction('已拒絕。'); } catch(e){ closeModal(); handle(e); } },
 'ai-stop': async (b) => { try { await api().AIStop(b.dataset.id); afterAIAction('已停止。'); } catch(e){ handle(e); } },
 'ai-user-done': async (b) => { try { await api().AIUserDone(b.dataset.id); afterAIAction('已標記為完成登入。'); } catch(e){ handle(e); } },
 'ai-revoke-grant': async (b) => { try { await api().AIRevokeGrant(b.dataset.key); afterAIAction('已撤銷網站授權。'); } catch(e){ handle(e); } },
 'ai-extend': (b) => dialog('延長網站授權', `<p>選擇的時間會加在目前的到期時刻之後；從現在起算最多 12 小時。</p><div class="approve">${durationPicker(60, 'ext')}<div class="form-actions"><button data-action="cancel-modal">取消</button><button class="primary" data-action="ai-extend-confirm" data-key="${esc(b.dataset.key)}">延長</button></div></div>`),
 'ai-extend-confirm': async (b) => {
  const m = readDuration(b.closest('.approve'));
  if(m === null) return;
  try { await api().AIExtendGrant(b.dataset.key, m); afterAIAction(`已延長 ${fmtDur(m)}。`); } catch(e){ closeModal(); handle(e); }
 },
 'ai-revoke-client': (b) => dialog('撤銷 AI 連線？', `<p>撤銷「${esc(b.dataset.name)}」後，它的權杖立即失效，進行中的工作與網站授權一併停止。之後要再用需重新配對。</p><div class="form-actions"><button data-action="cancel-modal">取消</button><button class="danger" data-action="ai-revoke-client-confirm" data-id="${esc(b.dataset.id)}">撤銷</button></div>`),
 'ai-revoke-client-confirm': async (b) => { try { await api().AIRevokeClient(b.dataset.id); afterAIAction('已撤銷 AI 連線。'); } catch(e){ closeModal(); handle(e); } },
 'ai-add-client': async () => {
  try { st.aiTools = await api().AIDetectTools(); } catch(e){ st.aiTools = []; }
  dialog('新增 AI 連線', `<form id="ai-client-form"><label for="ai-tool">AI 工具</label><select id="ai-tool">${AI_TOOLS.map(n => `<option>${n}</option>`).join('')}<option value="">其它（自行命名）</option></select><p class="small" id="ai-tool-status"></p><div id="ai-name-box"><label for="ai-name">顯示名稱（選填）</label><input id="ai-name" maxlength="40" placeholder="例如：公司筆電的 Claude Code"></div><p class="small muted">每個 AI 工具各自配對一個權杖，之後可個別撤銷。每次登入網站仍需你核准。</p><div class="field-error" id="form-error" role="alert"></div><div class="form-actions wrap"><button type="button" data-action="cancel-modal">取消</button><button type="submit" id="ai-manual">手動設定</button><button type="button" class="primary" id="ai-auto" data-action="ai-auto-setup">自動設定</button></div></form>`);
  aiToolStatus();
 },
 'ai-auto-setup': async (b) => {
  const tool = $('#ai-tool').value;
  b.disabled = true; b.textContent = '設定中…';
  try {
   const r = await api().AIAutoSetup(tool);
   dialog(`已自動設定 ${esc(tool)}`, `<p>Keyward 已把連線寫入 ${esc(tool)} 的設定，權杖不會顯示，也不需要複製。</p><dl class="ai-info"><dt>位置</dt><dd>${esc(r.where)}</dd>${r.backup ? `<dt>原檔備份</dt><dd>${esc(r.backup)}</dd>` : ''}</dl>${r.removedLegacy ? '<p class="small muted">已一併移除舊名稱 PASS_PW（passpw）的設定。</p>' : ''}${r.replaced ? `<p class="small muted">已撤銷 ${r.replaced} 個先前的 ${esc(tool)} 連線（它們的權杖已不在設定裡）。</p>` : ''}<div class="banner">${esc(r.restart)}</div><div class="form-actions"><button class="primary" data-action="ai-pairing-done">完成</button></div>`);
  } catch(e){
   b.disabled = false; b.textContent = '自動設定';
   handle(e, $('#form-error'));
  }
 },
 'ai-copy-snippet': (b) => {
  const s = st.aiSnippets?.[+b.dataset.i];
  if(!s) return;
  (navigator.clipboard ? navigator.clipboard.writeText(s.text).then(() => true, () => legacyCopy(s.text)) : Promise.resolve(legacyCopy(s.text)))
   .then(ok => note(ok === false ? '無法複製，請手動選取。' : '已複製設定。'));
 },
 'ai-pairing-done': () => { st.aiSnippets = null; afterAIAction(''); },
});

// Returns true when the form belonged to the AI page.
async function aiSubmit(f){
 if(f.id !== 'ai-client-form') return false;
 const tool = $('#ai-tool').value, name = ($('#ai-name').value.trim() || tool).trim();
 if(!name){ $('#form-error').textContent = '請輸入名稱。'; return true; }
 const res = await api().AIAddClient(name);
 const order = [...res.snippets].sort((a, b) => (b.tool === tool) - (a.tool === tool));
 st.aiSnippets = order;
 dialog('AI 連線已建立', `<div class="banner warn">權杖只會顯示這一次。設定檔裡的權杖等同這個連線的鑰匙；外流時請到 AI 代理頁撤銷。</div>${res.exeFound ? '' : `<div class="banner warn">找不到 keyward-mcp.exe（${esc(res.exe)}），請把它放在 Keyward 同一個資料夾。</div>`}${order.map((s, i) => `<h3>${esc(s.tool)}</h3><p class="small muted">${esc(s.where)}</p><pre class="snapshot">${esc(s.text)}</pre><button data-action="ai-copy-snippet" data-i="${i}">複製</button>`).join('')}<p class="small muted">設定好後重新啟動該 AI 工具。Keyward 需要開著，AI 才能提出登入要求。</p><div class="form-actions"><button class="primary" data-action="ai-pairing-done">完成</button></div>`);
 return true;
}

function aiToolStatus(){
 const sel = $('#ai-tool'); if(!sel) return;
 const tool = (st.aiTools || []).find(x => x.name === sel.value);
 const status = $('#ai-tool-status'), auto = $('#ai-auto'), manual = $('#ai-manual');
 $('#ai-name-box').hidden = !!(tool && tool.auto);
 if(tool && tool.auto){
  status.className = 'small';
  status.textContent = `✓ 已偵測到 ${tool.name}（${tool.where}）。按「自動設定」由 Keyward 寫入設定，會先備份原檔。`;
  auto.hidden = false; manual.classList.remove('primary');
 } else {
  status.className = 'small muted';
  status.textContent = tool ? `${tool.reason || '這台電腦上沒有偵測到它。'}請使用手動設定。` : '自行命名的工具請使用手動設定，依其文件加入 MCP 設定。';
  auto.hidden = true; manual.classList.add('primary');
 }
}
document.addEventListener('change', e => { if(e.target.id === 'ai-tool') aiToolStatus(); });
document.addEventListener('change', e => {
 if(!e.target.classList?.contains('dur')) return;
 const box = e.target.closest('.duration'), custom = e.target.value === 'custom';
 box.querySelector('.custom-dur').hidden = !custom;
 box.querySelector('.long-warn').hidden = (custom ? +box.querySelector('.dur-custom').value : +e.target.value) <= 120;
 box.querySelector('.dur-error').textContent = '';
 siteDurLabel(e.target);
});
document.addEventListener('input', e => {
 if(!e.target.classList?.contains('dur-custom')) return;
 const box = e.target.closest('.duration');
 box.querySelector('.long-warn').hidden = +e.target.value <= 120;
 box.querySelector('.dur-error').textContent = '';
 siteDurLabel(e.target);
});
function siteDurLabel(el){
 const label = el.closest('.approve')?.querySelector('.site-dur');
 if(!label) return;
 const sel = el.closest('.duration').querySelector('.dur');
 const m = sel.value === 'custom' ? Math.round(+el.closest('.duration').querySelector('.dur-custom').value) : +sel.value;
 label.textContent = m >= 15 && m <= MAX_GRANT ? `（${fmtDur(m)}）` : '';
}

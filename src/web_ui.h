#ifndef WEB_UI_H
#define WEB_UI_H

#include <Arduino.h>

const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NFC Tool</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh}
.container{max-width:720px;margin:0 auto;padding:12px}
h1{text-align:center;color:#00d4ff;margin:16px 0 8px;font-size:1.6em}
.subtitle{text-align:center;color:#666;font-size:0.85em;margin-bottom:14px}
.card{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:10px;padding:16px;margin-bottom:14px}
.card h2{color:#00d4ff;font-size:1.05em;margin-bottom:12px;border-bottom:1px solid #2a2a4a;padding-bottom:6px}
.btn{display:inline-block;padding:8px 18px;border:none;border-radius:6px;cursor:pointer;font-size:0.9em;font-weight:600;transition:all 0.2s}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.btn-primary{background:#0066cc;color:#fff}.btn-primary:hover:not(:disabled){background:#0077ee}
.btn-success{background:#00994d;color:#fff}.btn-success:hover:not(:disabled){background:#00b359}
.btn-danger{background:#cc3333;color:#fff}.btn-danger:hover:not(:disabled){background:#e04040}
.btn-warning{background:#cc8800;color:#fff}.btn-warning:hover:not(:disabled){background:#e09900}
.btn-sm{padding:5px 12px;font-size:0.8em}
.form-row{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.form-row label{min-width:80px;font-size:0.85em;color:#aaa}
input[type="text"],select{background:#0f0f1a;border:1px solid #3a3a5a;color:#e0e0e0;padding:6px 10px;border-radius:5px;font-family:'Consolas','Courier New',monospace;font-size:0.9em}
input[type="text"]:focus{outline:none;border-color:#00d4ff}
input[type="text"].uid-input{width:180px;text-transform:uppercase;letter-spacing:1px}
input[type="text"][readonly]{color:#888;border-color:#1a1a2e;cursor:default}
.radio-group{display:flex;gap:14px;align-items:center}
.radio-group label{min-width:auto;display:flex;align-items:center;gap:4px;cursor:pointer;font-size:0.9em}
input[type="radio"]{accent-color:#00d4ff}
.info-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;margin:8px 0}
.info-item{background:#0f0f1a;padding:6px 10px;border-radius:5px;font-size:0.85em}
.info-item span{color:#00d4ff;font-family:'Consolas',monospace}
.block-grid{max-height:400px;overflow-y:auto;background:#0f0f1a;border-radius:6px;padding:8px}
.block-row{display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid #1a1a2e}
.block-num{color:#666;font-family:'Consolas',monospace;font-size:0.8em;min-width:36px;text-align:right}
.block-data{background:transparent;border:1px solid transparent;color:#e0e0e0;padding:3px 6px;border-radius:3px;font-family:'Consolas',monospace;font-size:0.9em;flex:1;letter-spacing:1px;text-transform:uppercase}
.block-data:focus{border-color:#00d4ff;background:#0a0a15}
.block-data[readonly]{color:#888;cursor:default}
.block-data[readonly]:focus{border-color:transparent;background:transparent}
.dump-list{max-height:200px;overflow-y:auto}
.dump-item{display:flex;justify-content:space-between;align-items:center;padding:6px 8px;background:#0f0f1a;border-radius:5px;margin-bottom:4px}
.dump-name{font-family:'Consolas',monospace;font-size:0.9em;color:#00d4ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}
.status-bar{position:fixed;top:0;left:0;right:0;background:#1a1a2e;border-bottom:1px solid #2a2a4a;padding:4px 16px 3px;display:flex;flex-direction:column;gap:3px;z-index:100;font-size:0.8em}
.status-bar-row{display:flex;align-items:center;width:100%}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:5px}
.status-dot.ok{background:#00cc66}
.status-dot.busy{background:#ffaa00;animation:pulse 0.8s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);padding:10px 24px;border-radius:8px;font-size:0.9em;display:none;z-index:200;max-width:90%}
.toast-ok{background:#00663a;color:#fff}
.toast-err{background:#992222;color:#fff}
.spacer{height:52px}
/* Tabs */
.tabs{display:flex;gap:0;margin-bottom:14px;border-bottom:2px solid #2a2a4a}
.tab-btn{flex:1;padding:10px 0;text-align:center;font-size:1em;font-weight:600;color:#666;background:transparent;border:none;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all 0.2s}
.tab-btn.active{color:#00d4ff;border-bottom-color:#00d4ff}
.tab-btn:hover:not(.active){color:#aaa}
.tab-content{display:none}
.tab-content.active{display:block}
/* Toggle switch */
.toggle-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.toggle{position:relative;width:44px;height:24px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#3a3a5a;border-radius:12px;transition:0.3s}
.toggle-slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:#999;border-radius:50%;transition:0.3s}
.toggle input:checked+.toggle-slider{background:#0066cc}
.toggle input:checked+.toggle-slider:before{transform:translateX(20px);background:#fff}
.toggle-label{font-size:0.9em;color:#ccc}
/* Popup modal */
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:300;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:10px;padding:20px;max-width:400px;width:90%;text-align:center}
.modal h3{color:#cc8800;margin-bottom:12px;font-size:1.1em}
.modal p{margin-bottom:16px;font-size:0.9em;color:#ccc}
.modal .btn-group{display:flex;gap:8px;justify-content:center}
</style>
</head>
<body>

<div class="status-bar">
  <div class="status-bar-row">
    <div style="white-space:nowrap;flex-shrink:0"><span class="status-dot ok" id="statusDot"></span><span id="statusText">Ready</span></div>
    <span style="color:#333;flex-shrink:0;margin:0 6px">&middot;</span>
    <div style="display:flex;align-items:center;gap:6px;flex:1;min-width:0">
      <span style="color:#555;white-space:nowrap;flex-shrink:0">💾</span>
      <div style="flex:1;background:#0f0f1a;border-radius:2px;height:4px;overflow:hidden;min-width:0">
        <div id="spiffsBarFill" style="height:100%;background:#00994d;width:0%;transition:width 0.5s"></div>
      </div>
      <span id="spiffsBarText" style="color:#666;white-space:nowrap;flex-shrink:0">-</span>
    </div>
    <span style="color:#333;flex-shrink:0;margin:0 6px">&middot;</span>
    <div style="color:#666;white-space:nowrap;flex-shrink:0" id="ipDisplay"></div>
  </div>
</div>
<div class="spacer"></div>

<div class="container">
<h1>NFC Tool</h1>
<p class="subtitle">PN5180 ISO 15693 Reader/Writer</p>

<!-- Tabs -->
<div class="tabs">
  <button class="tab-btn active" data-tab="read" onclick="switchTab('read')">Read</button>
  <button class="tab-btn" data-tab="write" onclick="switchTab('write')">Write</button>
  <button class="tab-btn" data-tab="emulate" onclick="switchTab('emulate')">Emulate</button>
</div>

<!-- ==================== READ TAB ==================== -->
<div id="tab-read" class="tab-content active">

  <!-- Read Button -->
  <div class="card">
    <h2>Tag Operations</h2>
    <button class="btn btn-primary" onclick="doRead()">Read Tag</button>
  </div>

  <!-- Save -->
  <div class="card" id="readSaveCard">
    <h2>Save Dump</h2>
    <div class="form-row">
      <label>Name:</label>
      <input type="text" id="saveDumpName" placeholder="my_tag" style="flex:1">
      <button class="btn btn-success btn-sm" onclick="doSave()">Save</button>
      <button class="btn btn-primary btn-sm" onclick="doDownloadCurrent()">Download</button>
    </div>
  </div>

</div>

<!-- ==================== WRITE TAB ==================== -->
<div id="tab-write" class="tab-content">

  <!-- File Manager -->
  <div class="card">
    <h2>File Manager</h2>
    <div class="dump-list" id="dumpList">
      <div style="color:#666;text-align:center;padding:10px">No files saved yet.</div>
    </div>
    <div style="margin-top:8px">
      <input type="file" id="uploadFileInput" style="display:none" onchange="doUpload(this)">
      <button class="btn btn-primary btn-sm" onclick="document.getElementById('uploadFileInput').click()">Upload File</button>
    </div>
  </div>

  <!-- Write Operations -->
  <div class="card" id="writeOpsCard">
    <h2>Write Operations</h2>
    <div class="toggle-row">
      <label class="toggle">
        <input type="checkbox" id="toggleSetUid" onchange="onToggleSetUid()">
        <span class="toggle-slider"></span>
      </label>
      <span class="toggle-label">Set UID (magic card)</span>
    </div>
    <div id="csetuidOptions" style="display:none;margin-bottom:10px;padding-left:54px">
      <div class="form-row">
        <label>Version:</label>
        <div class="radio-group">
          <label><input type="radio" name="uidver" value="v1" checked> v1 (Gen1)</label>
          <label><input type="radio" name="uidver" value="v2"> v2 (Gen2)</label>
        </div>
      </div>
    </div>
    <button class="btn btn-warning" onclick="doWrite()">Write to Tag</button>
  </div>

</div>

<!-- ==================== EMULATE TAB ==================== -->
<div id="tab-emulate" class="tab-content">

  <!-- File Manager -->
  <div class="card">
    <h2>File Manager</h2>
    <div class="dump-list" id="emuDumpList">
      <div style="color:#666;text-align:center;padding:10px">No files saved yet.</div>
    </div>
  </div>

  <!-- Emulation Controls -->
  <div class="card" id="emuControlsCard">
    <h2>Emulation</h2>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <button class="btn btn-success" id="emuBtn" onclick="toggleEmulation()">Start Emulation</button>
      <span id="emuStatusLabel" style="font-size:0.9em;color:#888">Stopped</span>
    </div>
    <div style="background:#0f0f1a;border-radius:6px;padding:10px;font-size:0.85em">
      <div style="margin-bottom:6px">
        <span style="color:#aaa">Reader Field:</span>
        <span id="emuFieldStatus" style="margin-left:8px">-</span>
      </div>
      <div>
        <span style="color:#aaa">Commands Received:</span>
        <span id="emuCmdCount" style="color:#00d4ff;font-family:Consolas,monospace;margin-left:8px">0</span>
      </div>
    </div>
    <p style="margin-top:10px;font-size:0.75em;color:#555">Remove any physical tag from the reader before emulating. The PN5180 antenna will act as the emulated tag.</p>
  </div>

</div>

<!-- Shared Tag Info + Block Data (moved into active tab by JS) -->
<div id="sharedTagSection" style="display:none">
  <div class="card">
    <h2>Tag Info</h2>
    <div class="form-row">
      <label>UID:</label>
      <input type="text" id="sharedUid" class="uid-input" maxlength="16" value="">
    </div>
    <div class="info-grid">
      <div class="info-item">Blocks: <span id="sharedInfoBlocks">-</span></div>
      <div class="info-item">Block Size: <span id="sharedInfoBlockSize">-</span></div>
      <div class="info-item">DSFID: <input type="text" id="sharedInfoDsfid" maxlength="2" style="width:3em;font-family:'Consolas',monospace;font-size:0.9em;text-transform:uppercase" value="00"></div>
      <div class="info-item">AFI: <input type="text" id="sharedInfoAfi" maxlength="2" style="width:3em;font-family:'Consolas',monospace;font-size:0.9em;text-transform:uppercase" value="00"></div>
      <div class="info-item">IC Ref: <input type="text" id="sharedInfoIcRef" maxlength="2" style="width:3em;font-family:'Consolas',monospace;font-size:0.9em;text-transform:uppercase" value="00"></div>
    </div>
  </div>
  <div class="card">
    <h2>Block Data</h2>
    <div class="block-grid" id="sharedBlockGrid">
      <div style="color:#666;text-align:center;padding:20px">No data loaded.</div>
    </div>
  </div>
</div>

</div>

<!-- UID Mismatch Modal -->
<div class="modal-overlay" id="uidMismatchModal">
  <div class="modal">
    <h3>UID Mismatch</h3>
    <p id="uidMismatchMsg">The tag UID does not match the dump UID.</p>
    <div class="btn-group">
      <button class="btn btn-warning btn-sm" onclick="confirmWrite()">Write Anyway</button>
      <button class="btn btn-primary btn-sm" onclick="cancelWrite()">Cancel</button>
    </div>
  </div>
</div>

<!-- Rename Modal -->
<div class="modal-overlay" id="renameModal">
  <div class="modal">
    <h3>Rename File</h3>
    <div class="form-row" style="justify-content:center;margin-bottom:16px">
      <input type="text" id="renameInput" placeholder="new_name.json" style="width:220px">
    </div>
    <input type="hidden" id="renameOldName">
    <div class="btn-group">
      <button class="btn btn-success btn-sm" onclick="confirmRename()">Rename</button>
      <button class="btn btn-primary btn-sm" onclick="closeRename()">Cancel</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
let tagData = {uid:'',dsfid:'00',afi:'00',icRef:'00',blockSize:4,blockCount:0,blocks:[]};
let busy = false;

function setBusy(b, msg) {
  busy = b;
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  dot.className = 'status-dot ' + (b ? 'busy' : 'ok');
  txt.textContent = msg || (b ? 'Working...' : 'Ready');
  document.querySelectorAll('.btn').forEach(el => el.disabled = b);
}

function toast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = ok ? 'toast-ok' : 'toast-err';
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3000);
}

async function api(method, url, body) {
  if (busy) return null;
  setBusy(true);
  try {
    const opts = {method};
    if (body !== undefined) {
      opts.headers = {'Content-Type':'application/json'};
      opts.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const r = await fetch(url, opts);
    const j = await r.json();
    if (j.status === 'error') {
      toast(j.message || 'Error', false);
      return null;
    }
    return j;
  } catch(e) {
    toast('Connection error: ' + e.message, false);
    return null;
  } finally {
    setBusy(false);
  }
}

// ========== Tabs ==========

function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + tab));
  const sec = document.getElementById('sharedTagSection');
  if (tab === 'read') {
    const anchor = document.getElementById('readSaveCard');
    anchor.parentNode.insertBefore(sec, anchor);
    sec.style.display = '';
    updateSharedUI();
  } else if (tab === 'write') {
    const anchor = document.getElementById('writeOpsCard');
    anchor.parentNode.insertBefore(sec, anchor);
    sec.style.display = '';
    loadDumpList();
    updateSharedUI();
  } else if (tab === 'emulate') {
    const anchor = document.getElementById('emuControlsCard');
    anchor.parentNode.insertBefore(sec, anchor);
    sec.style.display = '';
    loadEmuDumpList();
    updateSharedUI();
  }
}

// ========== Shared Data ==========

function dataHexToBlocks(hex, blockSize) {
  const charsPerBlock = blockSize * 2;
  const blocks = [];
  for (let i = 0; i < hex.length; i += charsPerBlock) {
    blocks.push(hex.substring(i, i + charsPerBlock));
  }
  return blocks;
}

function blocksToDataHex() {
  return tagData.blocks.join('');
}

function formatBlock(hex) {
  return hex.match(/.{2}/g).join(' ');
}

// ========== Tag UI ==========

function updateSharedUI() {
  const uid = document.getElementById('sharedUid');
  if (!uid) return;
  uid.value = tagData.uid;
  document.getElementById('sharedInfoBlocks').textContent = tagData.blockCount || '-';
  document.getElementById('sharedInfoBlockSize').textContent = tagData.blockSize || '-';
  document.getElementById('sharedInfoDsfid').value = tagData.dsfid || '00';
  document.getElementById('sharedInfoAfi').value = tagData.afi || '00';
  document.getElementById('sharedInfoIcRef').value = tagData.icRef || '00';
  renderBlocks('sharedBlockGrid');
}

function renderBlocks(gridId, srcBlocks) {
  const blocks = srcBlocks || tagData.blocks;
  const grid = document.getElementById(gridId);
  if (!blocks.length) {
    grid.innerHTML = '<div style="color:#666;text-align:center;padding:20px">No data loaded.</div>';
    return;
  }
  let html = '';
  for (let i = 0; i < blocks.length; i++) {
    const formatted = formatBlock(blocks[i]);
    html += '<div class="block-row">' +
      '<span class="block-num">#' + String(i).padStart(2,'0') + '</span>' +
      '<input type="text" class="block-data" data-idx="'+i+'" value="'+formatted+'" oninput="onBlockEdit(this)">' +
      '</div>';
  }
  grid.innerHTML = html;
}

function onBlockEdit(el) {
  const idx = parseInt(el.dataset.idx);
  const raw = el.value.replace(/\s/g,'').toUpperCase();
  if (/^[0-9A-F]*$/.test(raw)) {
    tagData.blocks[idx] = raw;
  }
}

function collectMeta() {
  const uid = (document.getElementById('sharedUid')?.value || '').trim().toUpperCase();
  if (uid) tagData.uid = uid;
  const dsfid = (document.getElementById('sharedInfoDsfid')?.value || '').trim().toUpperCase();
  if (/^[0-9A-F]{1,2}$/.test(dsfid)) tagData.dsfid = dsfid.padStart(2,'0');
  const afi = (document.getElementById('sharedInfoAfi')?.value || '').trim().toUpperCase();
  if (/^[0-9A-F]{1,2}$/.test(afi)) tagData.afi = afi.padStart(2,'0');
  const icRef = (document.getElementById('sharedInfoIcRef')?.value || '').trim().toUpperCase();
  if (/^[0-9A-F]{1,2}$/.test(icRef)) tagData.icRef = icRef.padStart(2,'0');
}

function collectBlocks() {
  document.querySelectorAll('#sharedBlockGrid .block-data').forEach(el => {
    const idx = parseInt(el.dataset.idx);
    const raw = el.value.replace(/\s/g,'').toUpperCase();
    if (/^[0-9A-F]*$/.test(raw)) tagData.blocks[idx] = raw;
  });
}

// ========== Toggle & Modals ==========

function onToggleSetUid() {
  const show = document.getElementById('toggleSetUid').checked;
  document.getElementById('csetuidOptions').style.display = show ? 'block' : 'none';
}

function cancelWrite() {
  document.getElementById('uidMismatchModal').classList.remove('show');
}

let pendingWriteForce = false;

function confirmWrite() {
  document.getElementById('uidMismatchModal').classList.remove('show');
  pendingWriteForce = true;
  executeWrite();
}

// ========== API Calls ==========

async function doRead() {
  const r = await api('GET', '/api/read');
  if (!r || !r.data) return;
  const d = r.data;
  tagData.uid = d.uid || '';
  tagData.dsfid = d.dsfid || '00';
  tagData.afi = d.afi || '00';
  tagData.icRef = d.icRef || '00';
  tagData.blockSize = d.blockSize || 4;
  tagData.blockCount = d.blockCount || 0;
  tagData.blocks = dataHexToBlocks(d.data || '', tagData.blockSize);
  updateSharedUI();
  toast('Read ' + tagData.blockCount + ' blocks', true);
}

async function doWrite() {
  collectMeta();
  collectBlocks();
  if (!tagData.blocks.length) { toast('No data to write', false); return; }

  const setUid = document.getElementById('toggleSetUid').checked;
  const writeUid = document.getElementById('sharedUid').value.trim().toUpperCase();

  if (setUid) {
    // Will also set UID — validate it
    if (writeUid.length !== 16) { toast('UID must be 16 hex chars', false); return; }
    if (!writeUid.startsWith('E0')) { toast('UID must start with E0', false); return; }
    pendingWriteForce = false;
    await executeWrite();
  } else {
    // Check UID of tag on reader against loaded dump UID
    pendingWriteForce = false;
    // First read current tag UID
    setBusy(true, 'Checking tag...');
    try {
      const r = await fetch('/api/read');
      const j = await r.json();
      setBusy(false);
      if (j.status === 'error' || !j.data) {
        toast(j.message || 'Cannot read tag', false);
        return;
      }
      const tagUid = (j.data.uid || '').toUpperCase();
      if (writeUid && tagUid !== writeUid) {
        document.getElementById('uidMismatchMsg').textContent =
          'Tag UID: ' + tagUid + '\nDump UID: ' + writeUid + '\nThey do not match.';
        document.getElementById('uidMismatchModal').classList.add('show');
        return;
      }
      pendingWriteForce = true;
      await executeWrite();
    } catch(e) {
      setBusy(false);
      toast('Connection error', false);
    }
  }
}

async function executeWrite() {
  collectMeta();
  collectBlocks();
  const setUid = document.getElementById('toggleSetUid').checked;
  const writeUid = document.getElementById('sharedUid').value.trim().toUpperCase();

  // Write blocks
  const payload = {
    uid: writeUid,
    blockSize: tagData.blockSize,
    blockCount: tagData.blocks.length,
    data: blocksToDataHex()
  };
  const r = await api('POST', '/api/write', payload);
  if (!r) return;

  const written = r.written || 0;
  const tagBlocks = r.tagBlocks || 0;

  // Set UID if toggled
  if (setUid) {
    const ver = document.querySelector('input[name="uidver"]:checked').value;
    const r2 = await api('POST', '/api/csetuid', {uid: writeUid, version: ver});
    if (!r2) { toast('Wrote ' + written + ' blocks, but Set UID failed', false); return; }
    toast('Wrote ' + written + '/' + tagBlocks + ' blocks + Set UID', true);
  } else {
    toast('Wrote ' + written + '/' + tagBlocks + ' blocks', true);
  }
}

async function doSave() {
  collectMeta();
  collectBlocks();
  const stem = document.getElementById('saveDumpName').value.trim();
  if (!stem) { toast('Enter a dump name', false); return; }
  if (!/^[a-zA-Z0-9_\-]+$/.test(stem)) { toast('Name: letters, numbers, _ - only', false); return; }
  if (!tagData.blocks.length) { toast('No data to save', false); return; }
  const name = stem + '.json';
  const dump = {
    type: 'ISO15693',
    uid: tagData.uid,
    dsfid: tagData.dsfid,
    afi: tagData.afi,
    icRef: tagData.icRef,
    blockSize: tagData.blockSize,
    blockCount: tagData.blocks.length,
    data: blocksToDataHex()
  };
  const r = await api('POST', '/api/dump?name=' + encodeURIComponent(name), dump);
  if (r) { toast('Saved: ' + name, true); refreshSpiffs(); }
}

// ========== File Manager ==========

async function loadDumpList() {
  const r = await api('GET', '/api/dumps');
  if (!r) return;
  const list = r.dumps || [];
  const el = document.getElementById('dumpList');
  if (!list.length) {
    el.innerHTML = '<div style="color:#666;text-align:center;padding:10px">No files saved yet.</div>';
    return;
  }
  let html = '';
  for (const f of list) {
    const name = f.name;
    const sizeStr = formatSize(f.size);
    const isJson = name.toLowerCase().endsWith('.json');
    html += '<div class="dump-item">' +
      '<span class="dump-name" title="' + name + '">' + name + '</span>' +
      '<span style="font-size:0.75em;color:#555;margin-left:6px;white-space:nowrap">' + sizeStr + '</span>' +
      '<div style="display:flex;gap:4px;margin-left:auto">' +
      (isJson ? '<button class="btn btn-primary btn-sm" onclick="doLoad(\''+name+'\')">Load</button>' : '') +
      '<button class="btn btn-success btn-sm" onclick="doDownload(\''+name+'\')">Download</button>' +
      '<button class="btn btn-warning btn-sm" onclick="openRename(\''+name+'\')">Rename</button>' +
      '<button class="btn btn-danger btn-sm" onclick="doDelete(\''+name+'\')">Delete</button>' +
      '</div></div>';
  }
  el.innerHTML = html;
}

async function doLoad(name) {
  const r = await api('GET', '/api/dump?name=' + encodeURIComponent(name));
  if (!r || !r.data) return;
  const d = r.data;
  tagData.uid = d.uid || '';
  tagData.dsfid = d.dsfid || '00';
  tagData.afi = d.afi || '00';
  tagData.icRef = d.icRef || '00';
  tagData.blockSize = d.blockSize || 4;
  tagData.blockCount = d.blockCount || 0;
  tagData.blocks = dataHexToBlocks(d.data || '', tagData.blockSize);
  updateSharedUI();
  toast('Loaded: ' + name, true);
}

async function doDelete(name) {
  if (!confirm('Delete "' + name + '"?')) return;
  const r = await api('DELETE', '/api/dump?name=' + encodeURIComponent(name));
  if (r) { toast('Deleted: ' + name, true); loadDumpList(); refreshSpiffs(); }
}

function openRename(name) {
  document.getElementById('renameOldName').value = name;
  document.getElementById('renameInput').value = name;
  document.getElementById('renameModal').classList.add('show');
  setTimeout(() => document.getElementById('renameInput').focus(), 100);
}

function closeRename() {
  document.getElementById('renameModal').classList.remove('show');
}

async function confirmRename() {
  const oldName = document.getElementById('renameOldName').value;
  const newName = document.getElementById('renameInput').value.trim();
  if (!newName) { toast('Enter a name', false); return; }
  if (!/^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]*$/.test(newName)) { toast('Name: letters, numbers, _ - . only; no leading dot', false); return; }
  closeRename();
  const r = await api('POST', '/api/dump/rename', {oldName, newName});
  if (r) { toast('Renamed to: ' + newName, true); loadDumpList(); }
}

// ========== Emulate Tab ==========

let emuPolling = null;

async function loadEmuDumpList() {
  const r = await api('GET', '/api/dumps');
  if (!r) return;
  const list = r.dumps || [];
  const el = document.getElementById('emuDumpList');
  if (!list.length) {
    el.innerHTML = '<div style="color:#666;text-align:center;padding:10px">No files saved yet.</div>';
    return;
  }
  let html = '';
  for (const f of list) {
    const name = f.name;
    const sizeStr = formatSize(f.size);
    const isJson = name.toLowerCase().endsWith('.json');
    html += '<div class="dump-item">' +
      '<span class="dump-name" title="' + name + '">' + name + '</span>' +
      '<span style="font-size:0.75em;color:#555;margin-left:6px;white-space:nowrap">' + sizeStr + '</span>' +
      '<div style="display:flex;gap:4px;margin-left:auto">' +
      (isJson ? '<button class="btn btn-primary btn-sm" onclick="doEmuLoad(\''+name+'\')">Load</button>' : '') +
      '<button class="btn btn-success btn-sm" onclick="doDownload(\''+name+'\')">Download</button>' +
      '</div></div>';
  }
  el.innerHTML = html;
}

async function doEmuLoad(name) {
  const r = await api('GET', '/api/dump?name=' + encodeURIComponent(name));
  if (!r || !r.data) return;
  const d = r.data;
  tagData.uid = d.uid || '';
  tagData.dsfid = d.dsfid || '00';
  tagData.afi = d.afi || '00';
  tagData.icRef = d.icRef || '00';
  tagData.blockSize = d.blockSize || 4;
  tagData.blockCount = d.blockCount || 0;
  tagData.blocks = dataHexToBlocks(d.data || '', tagData.blockSize);
  updateSharedUI();
  toast('Loaded: ' + name, true);
}

async function toggleEmulation() {
  const btn = document.getElementById('emuBtn');
  if (btn.textContent === 'Stop Emulation') {
    await api('POST', '/api/emulate/stop');
    stopEmuPolling();
    btn.textContent = 'Start Emulation';
    btn.className = 'btn btn-success';
    document.getElementById('emuStatusLabel').textContent = 'Stopped';
    document.getElementById('emuFieldStatus').textContent = '-';
    document.getElementById('emuCmdCount').textContent = '0';
    toast('Emulation stopped', true);
    return;
  }
  if (!tagData.blocks.length) { toast('No data to emulate', false); return; }
  collectMeta();
  collectBlocks();
  const payload = {
    uid: document.getElementById('sharedUid').value.trim().toUpperCase(),
    dsfid: tagData.dsfid,
    afi: tagData.afi,
    icRef: tagData.icRef,
    blockSize: tagData.blockSize,
    blockCount: tagData.blocks.length,
    data: blocksToDataHex()
  };
  const r = await api('POST', '/api/emulate/start', payload);
  if (!r) return;
  btn.textContent = 'Stop Emulation';
  btn.className = 'btn btn-danger';
  document.getElementById('emuStatusLabel').textContent = 'Running...';
  startEmuPolling();
  toast('Emulation started', true);
}

function startEmuPolling() {
  stopEmuPolling();
  emuPolling = setInterval(pollEmuStatus, 500);
}

function stopEmuPolling() {
  if (emuPolling) { clearInterval(emuPolling); emuPolling = null; }
}

async function pollEmuStatus() {
  try {
    const r = await fetch('/api/emulate/status');
    const j = await r.json();
    if (!j.active) {
      stopEmuPolling();
      document.getElementById('emuBtn').textContent = 'Start Emulation';
      document.getElementById('emuBtn').className = 'btn btn-success';
      document.getElementById('emuStatusLabel').textContent = 'Stopped';
      return;
    }
    const fieldEl = document.getElementById('emuFieldStatus');
    if (j.fieldDetected) {
      fieldEl.innerHTML = '<span style="color:#00cc66">Detected</span>';
    } else {
      fieldEl.innerHTML = '<span style="color:#666">Not detected</span>';
    }
    document.getElementById('emuCmdCount').textContent = j.cmdCount;
  } catch(e) {}
}

// ========== Download ==========

function downloadJson(filename, jsonStr) {
  const blob = new Blob([jsonStr], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function doDownload(name) {
  if (busy) return;
  try {
    const r = await fetch('/api/rawfile?name=' + encodeURIComponent(name));
    if (!r.ok) { toast('Download failed', false); return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch(e) {
    toast('Download error: ' + e.message, false);
  }
}

function doDownloadCurrent() {
  collectMeta();
  collectBlocks();
  if (!tagData.blocks.length) { toast('No data to download', false); return; }
  const dump = {
    type: 'ISO15693',
    uid: tagData.uid,
    dsfid: tagData.dsfid,
    afi: tagData.afi,
    icRef: tagData.icRef,
    blockSize: tagData.blockSize,
    blockCount: tagData.blocks.length,
    data: blocksToDataHex()
  };
  const filename = tagData.uid || 'tag';
  downloadJson(filename, JSON.stringify(dump, null, 2));
}

// ========== Upload ==========

async function doUpload(input) {
  const file = input.files[0];
  input.value = '';
  if (!file) return;
  const name = file.name;
  if (!/^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]*$/.test(name)) { toast('Invalid filename', false); return; }
  setBusy(true, 'Uploading...');
  try {
    const fd = new FormData();
    fd.append('file', file, name);
    const r = await fetch('/api/upload?name=' + encodeURIComponent(name), {method:'POST', body:fd});
    const j = await r.json();
    if (j.status !== 'ok') { toast(j.message || 'Upload failed', false); return; }
    toast('Uploaded: ' + name, true);
    await loadDumpList();
    await loadEmuDumpList();
    refreshSpiffs();
  } catch(e) {
    toast('Upload error: ' + e.message, false);
  } finally {
    setBusy(false);
  }
}

// ========== SPIFFS Bar ==========

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  return (bytes / 1024).toFixed(1) + ' KB';
}

async function refreshSpiffs() {
  try {
    const r = await fetch('/api/spiffs');
    const j = await r.json();
    if (j.status !== 'ok') return;
    const pct = j.total > 0 ? Math.round(j.used / j.total * 100) : 0;
    const usedKb = (j.used / 1024).toFixed(1);
    const totalKb = Math.round(j.total / 1024);
    const fill = document.getElementById('spiffsBarFill');
    fill.style.width = pct + '%';
    fill.style.background = pct > 85 ? '#cc3333' : '#00994d';
    document.getElementById('spiffsBarText').textContent = usedKb + ' / ' + totalKb + ' KB (' + pct + '%)';
  } catch(e) {}
}

// ========== Init ==========
window.addEventListener('load', () => {
  document.getElementById('ipDisplay').textContent = location.host;
  switchTab('read');
  refreshSpiffs();
});
</script>
</body>
</html>
)rawliteral";

#endif

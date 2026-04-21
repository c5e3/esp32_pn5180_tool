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
.block-data:focus{outline:none;border-color:#00d4ff;background:#0a0a15}
.block-data[readonly]{color:#888;cursor:default}
.block-data[readonly]:focus{border-color:transparent;background:transparent}
/* MIFARE block coloring */
.block-row.blk-mfc-block0 .block-data{color:#ffd700;font-weight:bold}
.block-row.blk-mfc-block0 .block-num{color:#ffd700}
.block-row.blk-mfc-trailer .block-data{white-space:nowrap;overflow:hidden;line-height:1.2}
.block-row.blk-mfc-trailer .block-data .mfc-seg-key   {color:#4cff91;font-weight:bold}
.block-row.blk-mfc-trailer .block-data .mfc-seg-access{color:#ffd700;font-weight:bold}
.block-row.blk-mfc-unread .block-data{color:#444;font-style:italic}
.block-row.blk-mfc-unread .block-num{color:#333}
/* Tag type badge */
.tag-badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:0.7em;font-weight:bold;margin-left:6px;vertical-align:middle;text-transform:uppercase;letter-spacing:0.5px}
.tag-badge.ISO15693{background:#004d66;color:#00d4ff}
.tag-badge.MFC1K{background:#2a1a00;color:#ffa500}
.tag-badge.MFC4K{background:#1a2a00;color:#aaff44}
.tag-badge.MFCMINI{background:#2a2000;color:#ffdd44}
.tag-badge.MFUL{background:#001a2a;color:#44ddff}
.tag-badge.MFPLUS2K,.tag-badge.MFPLUS4K{background:#1a0026;color:#cc77ff}
.tag-badge.MFPLUS_SL2{background:#260013;color:#ff77aa}
.tag-badge.UNKNOWN{background:#2a2a2a;color:#888}
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
/* Collapsible section (Tools tab) */
.collapse-hdr{display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none;padding:10px 14px;background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;margin-bottom:8px}
.collapse-hdr:hover{border-color:#00d4ff}
.collapse-hdr .title{color:#00d4ff;font-weight:600;font-size:1em}
.collapse-hdr .arrow{color:#00d4ff;transition:transform 0.2s}
.collapse-hdr.open .arrow{transform:rotate(90deg)}
.collapse-body{display:none;padding:0 4px 8px}
.collapse-body.open{display:block}
.dict-toggle{display:flex;align-items:center;justify-content:space-between;padding:6px 8px;background:#0f0f1a;border-radius:5px;margin-bottom:4px;gap:8px}
.dict-toggle .name{font-family:'Consolas',monospace;font-size:0.85em;color:#00d4ff;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dict-toggle .meta{font-size:0.72em;color:#666;white-space:nowrap}
.dict-toggle .drag-handle{cursor:grab;color:#555;font-size:1.1em;padding:0 4px;user-select:none}
.dict-toggle .drag-handle:hover{color:#00d4ff}
.dict-toggle.dragging{opacity:0.4}
.dict-toggle.drop-above{border-top:2px solid #00d4ff;margin-top:2px}
.dict-toggle.drop-below{border-bottom:2px solid #00d4ff;margin-bottom:2px}
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
<h1>RFID Tool</h1>
<p class="subtitle">ESP32 &lt;-&gt; PN5180</p>

<!-- Tabs -->
<div class="tabs">
  <button class="tab-btn active" data-tab="read" onclick="switchTab('read')">Read</button>
  <button class="tab-btn" data-tab="write" onclick="switchTab('write')">Write</button>
  <button class="tab-btn" data-tab="emulate" onclick="switchTab('emulate')">Emulate</button>
  <button class="tab-btn" data-tab="tools" onclick="switchTab('tools')">Tools</button>
</div>

<!-- ==================== READ TAB ==================== -->
<div id="tab-read" class="tab-content active">

  <!-- Read Button + Progress -->
  <div class="card">
    <h2>Tag Operations</h2>
    <div style="display:flex;align-items:center;gap:10px">
      <button id="readBtn"   class="btn btn-primary" onclick="doRead()"       style="flex-shrink:0">Read Tag</button>
      <button id="cancelBtn" class="btn btn-danger"  onclick="doCancelRead()" style="flex-shrink:0;display:none" data-keep-enabled="true">Cancel Read</button>
      <div id="readProgress" style="flex:1;position:relative;background:#0f0f1a;border:1px solid #2a2a4a;border-radius:6px;height:34px;overflow:hidden">
        <div id="readProgressFill" style="position:absolute;top:0;left:0;bottom:0;background:#0066cc;width:0%;transition:width 0.2s"></div>
        <div id="readProgressText" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:0.82em;color:#bbb;font-family:Consolas,monospace;text-shadow:0 1px 2px #000">Idle</div>
      </div>
    </div>
  </div>

  <!-- Save -->
  <div class="card" id="readSaveCard">
    <h2>Save Dump</h2>
    <div class="form-row">
      <label>Name:</label>
      <input type="text" id="saveDumpName" style="flex:1">
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
      <span class="toggle-label" id="toggleSetUidLabel">Set UID (magic card)</span>
    </div>
    <div id="csetuidOptions" style="display:none;margin-bottom:10px;padding-left:54px">
      <div class="form-row">
        <label>Version:</label>
        <div class="radio-group">
          <label><input type="radio" name="uidver" value="v1">Gen1</label>
          <label><input type="radio" name="uidver" value="v2" checked>Gen2</label>
        </div>
      </div>
    </div>
    <div class="toggle-row" id="toggleWriteTrailersRow" style="display:none">
      <label class="toggle">
        <input type="checkbox" id="toggleWriteTrailers">
        <span class="toggle-slider"></span>
      </label>
      <span class="toggle-label" style="color:#ff9966">Write sector trailers (⚠ can brick sectors)</span>
    </div>
    <button class="btn btn-warning" onclick="doWrite()">Write to Tag</button>
    <div id="writeMagicHint" style="display:none;margin-top:8px;padding:8px;background:#0f0f1a;border-radius:5px;font-size:0.78em;color:#888">
      MIFARE Classic detected. Magic-card type (Gen 1A/1B, Gen 2 / CUID, Gen 3, Gen 4 GTU)
      is auto-detected at write time. “Set UID” toggles overwriting block 0 using whichever
      backdoor the card supports.
    </div>
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

<!-- ==================== TOOLS TAB ==================== -->
<div id="tab-tools" class="tab-content">

  <!-- Key Manager -->
  <div class="collapse-hdr" id="keyMgrHdr" onclick="toggleCollapse('keyMgr')">
    <span class="title">🔑 Key Manager</span>
    <span class="arrow">▶</span>
  </div>
  <div class="collapse-body" id="keyMgrBody">
    <div class="card">
      <h2>Dictionaries</h2>
      <p style="font-size:0.78em;color:#888;margin-bottom:8px">
        Files named <code>&lt;protocol&gt;_&lt;name&gt;.txt</code> in <code>/dicts/</code>
        (e.g. <code>mfc_std.txt</code>) are auto-discovered. Disable a dictionary to skip it during reads.
      </p>
      <div class="dump-list" id="dictList">
        <div style="color:#666;text-align:center;padding:10px">Loading…</div>
      </div>
      <div style="margin-top:8px">
        <input type="file" id="dictUploadInput" style="display:none" onchange="doUploadDict(this)">
        <button class="btn btn-primary btn-sm" onclick="document.getElementById('dictUploadInput').click()">Upload Dictionary</button>
      </div>
    </div>
  </div>

  <!-- Card Fingerprint (proxmark `hf mf info` port) -->
  <div class="collapse-hdr" id="cidentHdr" onclick="toggleCollapse('cident')">
    <span class="title">🔍 Card Fingerprint</span>
    <span class="arrow">▶</span>
  </div>
  <div class="collapse-body" id="cidentBody">
    <div class="card">
      <h2>MIFARE Classic Clone Detection</h2>
      <p style="font-size:0.78em;color:#888;margin-bottom:8px">
        Probes for magic-card capabilities (Gen 1A/1B, Gen 2 / CUID, Gen 3, Gen 4 GTU,
        Gen 4 GDM / USCUID, FUID, Super Card) and tries known Fudan / NXP / Infineon
        backdoor keys. If a backdoor matches, block 0 is read and matched against
        a known-clone fingerprint table. PRNG / static-nonce checks aren't possible
        on PN5180.
      </p>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <button class="btn btn-primary" onclick="doIdentCard()" style="flex-shrink:0">Identify Card</button>
        <span id="cidentStatus" style="font-size:0.85em;color:#bbb">Idle</span>
      </div>
      <div id="cidentResult" style="font-family:Consolas,monospace;font-size:0.82em;background:#0f0f1a;border:1px solid #2a2a4a;border-radius:6px;padding:10px;min-height:60px;white-space:pre-wrap;color:#ddd"></div>
    </div>
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
      <div class="info-item">Type: <span id="sharedInfoType">-</span></div>
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
      <input type="text" id="renameInput" style="width:220px">
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
  // Disable every button while busy EXCEPT those opted out via data-keep-enabled
  // (the Cancel Read button needs to stay clickable during a read).
  document.querySelectorAll('.btn').forEach(el => {
    if (el.dataset.keepEnabled === 'true') return;
    el.disabled = b;
  });
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
  } else if (tab === 'tools') {
    sec.style.display = 'none';
    loadDictList();
  }
}

// ========== Collapsible ==========
function toggleCollapse(name) {
  const hdr = document.getElementById(name + 'Hdr');
  const body = document.getElementById(name + 'Body');
  const open = !hdr.classList.contains('open');
  hdr.classList.toggle('open', open);
  body.classList.toggle('open', open);
  if (open && name === 'keyMgr') loadDictList();
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
  const typeEl = document.getElementById('sharedInfoType');
  if (typeEl) {
    typeEl.innerHTML = tagData.type
      ? '<span class="tag-badge ' + tagData.type + '">' + tagData.type + '</span>'
      : '-';
  }
  document.getElementById('sharedInfoBlocks').textContent = tagData.blockCount || '-';
  document.getElementById('sharedInfoBlockSize').textContent = tagData.blockSize || '-';
  document.getElementById('sharedInfoDsfid').value = tagData.dsfid || '00';
  document.getElementById('sharedInfoAfi').value = tagData.afi || '00';
  document.getElementById('sharedInfoIcRef').value = tagData.icRef || '00';
  renderBlocks('sharedBlockGrid');
  updateWriteUiForType();
}

// Show/hide MFC-only write controls and adjust labels based on tag type
function updateWriteUiForType() {
  const t = tagData.type || 'ISO15693';
  const isMFC  = t.startsWith('MFC') || t.startsWith('MFPLUS');
  const isMFUL = (t === 'MFUL');
  const setUidLabel = document.getElementById('toggleSetUidLabel');
  const verRow      = document.getElementById('csetuidOptions');
  const trailersRow = document.getElementById('toggleWriteTrailersRow');
  const magicHint   = document.getElementById('writeMagicHint');
  const setUidRow   = document.getElementById('toggleSetUid');
  if (!setUidLabel) return;

  if (isMFC) {
    setUidLabel.textContent = 'Write block 0 (UID via magic backdoor)';
    trailersRow.style.display = '';
    magicHint.style.display   = '';
    // Gen1/Gen2 radio is ISO15693-specific — hide for MFC
    if (setUidRow.checked) verRow.style.display = 'none';
    setUidRow.parentElement.parentElement.dataset.iso = 'false';
  } else if (isMFUL) {
    setUidLabel.textContent = 'Set UID (not supported on plain Ultralight)';
    trailersRow.style.display = 'none';
    magicHint.style.display   = 'none';
  } else {
    // ISO 15693 (default)
    setUidLabel.textContent = 'Set UID (magic card)';
    trailersRow.style.display = 'none';
    magicHint.style.display   = 'none';
    if (setUidRow.checked) verRow.style.display = '';
  }
}

function renderBlocks(gridId, srcBlocks) {
  const blocks = srcBlocks || tagData.blocks;
  const grid = document.getElementById(gridId);
  if (!blocks.length) {
    grid.innerHTML = '<div style="color:#666;text-align:center;padding:20px">No data loaded.</div>';
    return;
  }
  const type = tagData.type || 'ISO15693';
  const isMFC = type.startsWith('MFC') || type.startsWith('MFPLUS');
  const isMFUL = (type === 'MFUL');
  const blockRead = tagData.blockRead || [];
  const keyUsed = tagData.keyUsed || [];

  // Build sector layout lookup for MIFARE Classic
  function sectorOfBlock(b) {
    if (type === 'MFC4K' || type === 'MFPLUS4K') {
      return b < 128 ? Math.floor(b/4) : 32 + Math.floor((b-128)/16);
    }
    return Math.floor(b/4);
  }
  function sectorTrailer(s) {
    if ((type === 'MFC4K' || type === 'MFPLUS4K') && s >= 32) return 128 + (s-32)*16 + 15;
    return s*4 + 3;
  }
  function sectorFirstBlock(s) {
    if ((type === 'MFC4K' || type === 'MFPLUS4K') && s >= 32) return 128 + (s-32)*16;
    return s*4;
  }

  let html = '';
  for (let i = 0; i < blocks.length; i++) {
    let rowClass = 'block-row';
    let label = '';
    let isTrailer = false;

    if (isMFC) {
      const isRead = blockRead[i] !== false;  // default true for loaded data
      if (!isRead) {
        rowClass += ' blk-mfc-unread';
      } else if (i === 0) {
        rowClass += ' blk-mfc-block0';
        label = ' <span style="font-size:0.7em;color:#ffd700">[MFR]</span>';
      } else {
        const s = sectorOfBlock(i);
        const trailer = sectorTrailer(s);
        if (i === trailer) {
          isTrailer = true;
          rowClass += ' blk-mfc-trailer';
          const ku = keyUsed[s] || 0;
          label = ' <span style="font-size:0.7em;color:#888">[Sec' + s + ' trailer' +
            (ku === 1 ? ' <span style="color:#4cff91">KeyA</span>' :
             ku === 2 ? ' <span style="color:#ff5c5c">KeyB</span>' : '') + ']</span>';
        }
      }
    }

    let dataHtml;
    if (isTrailer) {
      // contenteditable div with colored spans: [KeyA 6B][AccessBits+GPB 4B][KeyB 6B]
      dataHtml = '<div class="block-data" contenteditable="true" spellcheck="false" ' +
                 'data-idx="'+i+'" ' +
                 'onkeydown="if(event.key===\'Enter\')event.preventDefault()" ' +
                 'oninput="onTrailerEdit(this)">' +
                 trailerColoredHtml(blocks[i]) +
                 '</div>';
    } else {
      dataHtml = '<input type="text" class="block-data" data-idx="'+i+'" value="'+formatBlock(blocks[i])+'" oninput="onBlockEdit(this)">';
    }

    html += '<div class="' + rowClass + '">' +
      '<span class="block-num">#' + String(i).padStart(2,'0') + '</span>' +
      dataHtml +
      label +
      '</div>';

    // After MFC trailer, show sector separator
    if (isMFC && i > 0) {
      const s = sectorOfBlock(i);
      const trailer = sectorTrailer(s);
      const nextS = sectorOfBlock(i+1);
      if (i === trailer && i < blocks.length - 1) {
        html += '<div style="height:3px;background:#1a1a2e;margin:2px 0"></div>';
      }
    }
  }
  grid.innerHTML = html;
}

function onBlockEdit(el) {
  const idx = parseInt(el.dataset.idx);
  const raw = el.value.replace(/\s/g,'').toUpperCase();
  if (/^[0-9A-F]*$/.test(raw)) tagData.blocks[idx] = raw;
}

// ---- Sector-trailer colored editor ----
// Re-renders a contenteditable div with three colored spans on each keystroke,
// restoring the caret by counting hex chars (spaces/non-hex ignored) from the start.

function trailerColoredHtml(hex) {
  const keyA = (hex.slice(0, 12).match(/.{1,2}/g) || []).join(' ');
  const acc  = (hex.slice(12, 20).match(/.{1,2}/g) || []).join(' ');
  const keyB = (hex.slice(20, 32).match(/.{1,2}/g) || []).join(' ');
  const parts = [];
  if (keyA) parts.push('<span class="mfc-seg-key">' + keyA + '</span>');
  if (acc)  parts.push('<span class="mfc-seg-access">' + acc + '</span>');
  if (keyB) parts.push('<span class="mfc-seg-key">' + keyB + '</span>');
  return parts.join(' ') || '<span class="mfc-seg-key">​</span>';
}

function getTrailerCaretHex(el) {
  const sel = window.getSelection();
  if (!sel.rangeCount) return 0;
  const r = sel.getRangeAt(0).cloneRange();
  r.selectNodeContents(el);
  r.setEnd(sel.getRangeAt(0).endContainer, sel.getRangeAt(0).endOffset);
  return r.toString().replace(/[^0-9A-Fa-f]/g,'').length;
}

function setTrailerCaretHex(el, pos) {
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
  let node, remaining = pos;
  while ((node = walker.nextNode())) {
    const t = node.nodeValue;
    for (let i = 0; i <= t.length; i++) {
      if (remaining === 0) {
        const r = document.createRange();
        r.setStart(node, i); r.collapse(true);
        const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        return;
      }
      if (i < t.length && /[0-9A-Fa-f]/.test(t[i])) remaining--;
    }
  }
  const r = document.createRange();
  r.selectNodeContents(el); r.collapse(false);
  const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
}

function onTrailerEdit(el) {
  const idx = parseInt(el.dataset.idx);
  const caretBefore = getTrailerCaretHex(el);
  const hex = (el.textContent || '').replace(/[^0-9A-Fa-f]/g,'').toUpperCase().slice(0, 32);
  tagData.blocks[idx] = hex;
  el.innerHTML = trailerColoredHtml(hex);
  setTrailerCaretHex(el, Math.min(caretBefore, hex.length));
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
    const text = (el.tagName === 'DIV') ? (el.textContent || '') : el.value;
    const raw = text.replace(/[^0-9A-Fa-f]/g,'').toUpperCase();
    if (/^[0-9A-F]*$/.test(raw)) tagData.blocks[idx] = raw;
  });
}

// ========== Toggle & Modals ==========

function onToggleSetUid() {
  const checked = document.getElementById('toggleSetUid').checked;
  const t = tagData.type || 'ISO15693';
  const isMFC = t.startsWith('MFC') || t.startsWith('MFPLUS');
  // Gen1/Gen2 version radios only relevant for ISO15693 — hide for MFC
  document.getElementById('csetuidOptions').style.display =
    (checked && !isMFC) ? 'block' : 'none';
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

function setReadProgress(pct, text) {
  const fill = document.getElementById('readProgressFill');
  const txt  = document.getElementById('readProgressText');
  if (fill) fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
  if (txt)  txt.textContent = text;
}

function updateReadProgress(j) {
  const phase = j.phase | 0;
  const block = j.block | 0;
  const total = j.totalBlocks | 0;
  const kt    = j.keyType;
  if (phase === 1 || total <= 0) {
    setReadProgress(3, 'Detecting tag...');
    return;
  }
  const pct = Math.round((block + 1) / total * 100);
  const keyStr = (kt === 0) ? 'Key A' : (kt === 1) ? 'Key B' : '-';
  const verb = (phase === 3) ? 'Read' : 'Auth';
  setReadProgress(pct, verb + ' block ' + block + '/' + (total - 1) + ' · ' + keyStr + ' · ' + pct + '%');
}

async function doRead() {
  if (busy) return;
  setBusy(true);
  setReadButton(true);
  setReadProgress(1, 'Starting...');
  try {
    let j;
    // First call kicks off the background task; subsequent calls poll.
    while (true) {
      const r = await fetch('/api/read');
      j = await r.json();
      if (j.status !== 'running') break;
      updateReadProgress(j);
      await new Promise(res => setTimeout(res, 200));
    }
    if (j.status === 'error') {
      setReadProgress(0, j.message || 'Error');
      toast(j.message || 'Error', false);
      return;
    }
    if (!j.data) { setReadProgress(0, 'Idle'); return; }

    const d = j.data;
    tagData.type = d.type || 'ISO15693';
    tagData.uid = d.uid || '';
    tagData.blockCount = d.blockCount || 0;
    tagData.blockRead = d.blockRead ? d.blockRead.split('').map(c => c === '1') : [];
    tagData.keyUsed = d.keyUsed ? d.keyUsed.split('').map(c => parseInt(c)) : [];

    const isMFC = tagData.type.startsWith('MFC') || tagData.type.startsWith('MFPLUS');
    const isMFUL = tagData.type === 'MFUL';

    if (isMFC || isMFUL) {
      tagData.blockSize = d.blockSize || (isMFUL ? 4 : 16);
      tagData.dsfid = '00'; tagData.afi = '00'; tagData.icRef = '00';
    } else {
      tagData.blockSize = d.blockSize || 4;
      tagData.dsfid = d.dsfid || '00';
      tagData.afi = d.afi || '00';
      tagData.icRef = d.icRef || '00';
    }
    tagData.blocks = dataHexToBlocks(d.data || '', tagData.blockSize);
    updateSharedUI();
    const unread = tagData.blockRead.filter(v => !v).length;
    const msg = 'Read ' + tagData.type + ': ' + tagData.blockCount + ' blocks' +
      (unread > 0 ? ' (' + unread + ' locked)' : '');
    setReadProgress(100, 'Done · ' + tagData.blockCount + ' blocks' + (unread > 0 ? ' (' + unread + ' locked)' : ''));
    toast(msg, true);
  } catch(e) {
    setReadProgress(0, 'Error');
    toast('Connection error: ' + e.message, false);
  } finally {
    setBusy(false);
    setReadButton(false);
  }
}

// Toggle Read ↔ Cancel button. Only one is visible at a time.
function setReadButton(reading) {
  document.getElementById('readBtn').style.display   = reading ? 'none' : '';
  document.getElementById('cancelBtn').style.display = reading ? '' : 'none';
}

// POST cancel — server flips a flag; the running readTask aborts at its next
// check point and resolves the polling loop with status:"error","Cancelled".
async function doCancelRead() {
  const btn = document.getElementById('cancelBtn');
  btn.disabled = true;
  btn.textContent = 'Cancelling...';
  try {
    await fetch('/api/read/cancel', {method: 'POST'});
  } catch(e) {
    // ignore — the polling loop will surface the error
  } finally {
    // Re-enable for the next read; visibility is reset by setReadButton(false)
    btn.disabled = false;
    btn.textContent = 'Cancel Read';
  }
}

async function doWrite() {
  collectMeta();
  collectBlocks();
  if (!tagData.blocks.length) { toast('No data to write', false); return; }

  const t = tagData.type || 'ISO15693';
  const isMFC  = t.startsWith('MFC') || t.startsWith('MFPLUS');
  const isMFUL = (t === 'MFUL');

  // ── MIFARE Classic / Ultralight: dispatch directly, no UID-mismatch modal ──
  // Magic capability and any required block-0 backdoor are auto-detected on the
  // device side; the UI just forwards the dump + setUid/writeTrailers flags.
  if (isMFC || isMFUL) {
    pendingWriteForce = true;
    await executeWrite();
    return;
  }

  // ── ISO 15693: original UID-mismatch flow ──
  const setUid = document.getElementById('toggleSetUid').checked;
  const writeUid = document.getElementById('sharedUid').value.trim().toUpperCase();

  if (setUid) {
    if (writeUid.length !== 16) { toast('UID must be 16 hex chars', false); return; }
    if (!writeUid.startsWith('E0')) { toast('UID must start with E0', false); return; }
    pendingWriteForce = false;
    await executeWrite();
  } else {
    pendingWriteForce = false;
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
  const t = tagData.type || 'ISO15693';
  const isMFC  = t.startsWith('MFC') || t.startsWith('MFPLUS');
  const isMFUL = (t === 'MFUL');

  // Build payload — the device dispatches on the `type` field
  const payload = {
    type: t,
    uid: writeUid,
    blockSize: tagData.blockSize,
    blockCount: tagData.blocks.length,
    data: blocksToDataHex()
  };
  if (isMFC) {
    payload.setUid        = setUid;
    payload.writeTrailers = document.getElementById('toggleWriteTrailers').checked;
  }

  const r = await api('POST', '/api/write', payload);
  if (!r) return;

  const written = r.written | 0;

  if (isMFC) {
    const m = r.magic | 0;
    // Bit names match enum MagicType in PN5180MIFARE.h
    const flags = [];
    if (m & 0x01) flags.push('Gen 1A');
    if (m & 0x02) flags.push('Gen 1B');
    if (m & 0x04) flags.push('Gen 2 / CUID');
    if (m & 0x08) flags.push('Gen 3');
    if (m & 0x10) flags.push('Gen 4 GTU');
    if (m & 0x20) flags.push('GDM');
    const tag = flags.length ? ' (' + flags.join(', ') + ')' : ' (no magic detected)';
    toast('Wrote ' + written + ' blocks' + tag, true);
    return;
  }

  if (isMFUL) {
    toast('Wrote ' + written + ' pages', true);
    return;
  }

  // ISO 15693 path — may also need to set UID via legacy /api/csetuid
  const tagBlocks = r.tagBlocks || 0;
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
  const type = tagData.type || 'ISO15693';
  const isMFC = type.startsWith('MFC') || type.startsWith('MFPLUS');
  const isMFUL = type === 'MFUL';
  let dump;
  if (isMFC || isMFUL) {
    dump = {
      type: type,
      uid: tagData.uid,
      sak: tagData.sak || '00',
      atqa: tagData.atqa || '0000',
      blockSize: tagData.blockSize,
      blockCount: tagData.blocks.length,
      data: blocksToDataHex(),
      blockRead: (tagData.blockRead || []).map(v => v ? '1' : '0').join(''),
      keyUsed: (tagData.keyUsed || []).join('')
    };
  } else {
    dump = {
      type: 'ISO15693',
      uid: tagData.uid,
      dsfid: tagData.dsfid,
      afi: tagData.afi,
      icRef: tagData.icRef,
      blockSize: tagData.blockSize,
      blockCount: tagData.blocks.length,
      data: blocksToDataHex()
    };
  }
  const r = await api('POST', '/api/dump?name=' + encodeURIComponent(name), dump);
  if (r) {
    toast('Saved: ' + name, true);
    await loadDumpList();
    await loadEmuDumpList();
    refreshSpiffs();
  }
}

// ========== File Manager ==========

async function loadDumpList() {
  const r = await api('GET', '/api/dumps?folder=dumps');
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
    const typeTag = f.type ? '<span class="tag-badge ' + f.type + '">' + f.type + '</span>' : '';
    html += '<div class="dump-item">' +
      '<span class="dump-name" title="' + name + '">' + name + '</span>' +
      typeTag +
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
  tagData.type = d.type || 'ISO15693';
  tagData.uid = d.uid || '';
  const isMFC = tagData.type.startsWith('MFC') || tagData.type.startsWith('MFPLUS');
  const isMFUL = tagData.type === 'MFUL';
  if (isMFC || isMFUL) {
    tagData.blockSize = d.blockSize || (isMFUL ? 4 : 16);
    tagData.sak = d.sak || '00';
    tagData.atqa = d.atqa || '0000';
    tagData.dsfid = '00'; tagData.afi = '00'; tagData.icRef = '00';
    tagData.blockRead = d.blockRead ? d.blockRead.split('').map(c => c === '1') : [];
    tagData.keyUsed = d.keyUsed ? d.keyUsed.split('').map(c => parseInt(c)) : [];
  } else {
    tagData.blockSize = d.blockSize || 4;
    tagData.dsfid = d.dsfid || '00';
    tagData.afi = d.afi || '00';
    tagData.icRef = d.icRef || '00';
    tagData.blockRead = [];
    tagData.keyUsed = [];
  }
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
  const r = await api('GET', '/api/dumps?folder=dumps');
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
    const typeTag = f.type ? '<span class="tag-badge ' + f.type + '">' + f.type + '</span>' : '';
    html += '<div class="dump-item">' +
      '<span class="dump-name" title="' + name + '">' + name + '</span>' +
      typeTag +
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
  let uploadOk = false;
  try {
    const fd = new FormData();
    fd.append('file', file, name);
    const r = await fetch('/api/upload?name=' + encodeURIComponent(name), {method:'POST', body:fd});
    const j = await r.json();
    if (j.status !== 'ok') { toast(j.message || 'Upload failed', false); return; }
    toast('Uploaded: ' + name, true);
    uploadOk = true;
  } catch(e) {
    toast('Upload error: ' + e.message, false);
  } finally {
    setBusy(false);
  }
  // Refresh AFTER busy is cleared, otherwise api() short-circuits.
  if (uploadOk) {
    await loadDumpList();
    await loadEmuDumpList();
    refreshSpiffs();
  }
}

// ========== Card Fingerprint (Tools tab) ==========

async function doIdentCard() {
  if (busy) return;
  const status = document.getElementById('cidentStatus');
  const result = document.getElementById('cidentResult');
  setBusy(true);
  status.textContent = 'Probing card... (~1s)';
  result.textContent = '';
  try {
    const r = await fetch('/api/cident');
    const j = await r.json();
    if (j.err) {
      status.textContent = j.err === 'no_tag' ? 'No tag detected' : ('Error: ' + j.err);
      toast(j.err === 'no_tag' ? 'No tag detected' : ('Error: ' + j.err), false);
      return;
    }
    status.textContent = 'Done';
    let out = '';
    out += 'UID:    ' + (j.uid || '?') + '\n';
    out += 'SAK:    ' + (j.sak || '?') + '\n';
    out += 'ATQA:   ' + (j.atqa || '?') + '\n';
    out += 'Type:   ' + (j.type || '?') + '\n';
    out += '\nMagic capabilities:\n';
    if (j.magic && j.magic.length) {
      j.magic.forEach(m => out += '  • ' + m + '\n');
    } else {
      out += '  (none detected)\n';
    }
    if (j.backdoor) {
      out += '\nBackdoor key:  ' + j.backdoor.name + '  (' + j.backdoor.key + ')\n';
    }
    if (j.block0) {
      out += '\nBlock 0:  ' + j.block0 + '\n';
    }
    if (j.fingerprint) {
      out += '\nFingerprint:  ' + j.fingerprint + '\n';
    }
    result.textContent = out;
  } catch(e) {
    status.textContent = 'Connection error';
    toast('Connection error: ' + e.message, false);
  } finally {
    setBusy(false);
  }
}

// ========== Key Manager (Tools tab) ==========

async function loadDictList() {
  const r = await api('GET', '/api/dumps?folder=dicts');
  if (!r) return;
  const list = r.dumps || [];
  const el = document.getElementById('dictList');
  if (!list.length) {
    el.innerHTML = '<div style="color:#666;text-align:center;padding:10px">No dictionaries.</div>';
    return;
  }
  let html = '';
  for (const f of list) {
    const name = f.name;
    const enabled = f.enabled !== false;
    const sizeStr = formatSize(f.size);
    const safe = name.replace(/'/g, "\\'");
    html += '<div class="dict-toggle" draggable="true" data-name="' + name + '">' +
      '<span class="drag-handle" title="Drag to reorder">⋮⋮</span>' +
      '<label class="toggle" title="Enable/disable for reads">' +
        '<input type="checkbox"' + (enabled ? ' checked' : '') +
          ' onchange="toggleDict(\'' + safe + '\', this.checked)">' +
        '<span class="toggle-slider"></span>' +
      '</label>' +
      '<span class="name" title="' + name + '">' + name + '</span>' +
      '<span class="meta">' + sizeStr + '</span>' +
      '<button class="btn btn-success btn-sm" onclick="doDownloadDict(\'' + safe + '\')">⬇</button>' +
      '<button class="btn btn-danger btn-sm" onclick="doDeleteDict(\'' + safe + '\')">✕</button>' +
      '</div>';
  }
  el.innerHTML = html;
  attachDictDnD();
}

// ----- Drag-and-drop reordering -----
let dictDragSrc = null;

function attachDictDnD() {
  const list = document.getElementById('dictList');
  list.querySelectorAll('.dict-toggle').forEach(row => {
    row.addEventListener('dragstart', e => {
      dictDragSrc = row;
      row.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      // Required for Firefox
      e.dataTransfer.setData('text/plain', row.dataset.name);
    });
    row.addEventListener('dragend', () => {
      row.classList.remove('dragging');
      list.querySelectorAll('.dict-toggle').forEach(r => {
        r.classList.remove('drop-above', 'drop-below');
      });
      dictDragSrc = null;
    });
    row.addEventListener('dragover', e => {
      e.preventDefault();
      if (!dictDragSrc || dictDragSrc === row) return;
      const rect = row.getBoundingClientRect();
      const above = (e.clientY - rect.top) < rect.height / 2;
      row.classList.toggle('drop-above', above);
      row.classList.toggle('drop-below', !above);
    });
    row.addEventListener('dragleave', () => {
      row.classList.remove('drop-above', 'drop-below');
    });
    row.addEventListener('drop', async e => {
      e.preventDefault();
      if (!dictDragSrc || dictDragSrc === row) return;
      const rect = row.getBoundingClientRect();
      const above = (e.clientY - rect.top) < rect.height / 2;
      row.classList.remove('drop-above', 'drop-below');
      if (above) row.parentNode.insertBefore(dictDragSrc, row);
      else       row.parentNode.insertBefore(dictDragSrc, row.nextSibling);
      await saveDictOrder();
    });
  });
}

async function saveDictOrder() {
  const order = Array.from(document.querySelectorAll('#dictList .dict-toggle'))
    .map(r => r.dataset.name);
  const r = await api('POST', '/api/dicts/order', order);
  if (r) toast('Order saved', true);
  else loadDictList();  // revert on failure
}

async function toggleDict(name, enabled) {
  const r = await api('POST', '/api/dicts/toggle', {name, enabled});
  if (r) toast((enabled ? 'Enabled: ' : 'Disabled: ') + name, true);
  else loadDictList();  // revert on failure
}

async function doDeleteDict(name) {
  if (!confirm('Delete dictionary "' + name + '"?')) return;
  const r = await api('DELETE', '/api/dump?folder=dicts&name=' + encodeURIComponent(name));
  if (r) { toast('Deleted: ' + name, true); loadDictList(); refreshSpiffs(); }
}

async function doDownloadDict(name) {
  if (busy) return;
  try {
    const r = await fetch('/api/rawfile?folder=dicts&name=' + encodeURIComponent(name));
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

async function doUploadDict(input) {
  const file = input.files[0];
  input.value = '';
  if (!file) return;
  const name = file.name;
  if (!/^[a-zA-Z0-9]+_[a-zA-Z0-9_\-]+\.txt$/i.test(name) || name.toLowerCase() === 'config.json') {
    toast('Filename must match <protocol>_<name>.txt', false);
    return;
  }
  setBusy(true, 'Uploading...');
  let uploadOk = false;
  try {
    const fd = new FormData();
    fd.append('file', file, name);
    const r = await fetch('/api/upload?folder=dicts&name=' + encodeURIComponent(name), {method:'POST', body:fd});
    const j = await r.json();
    if (j.status !== 'ok') { toast(j.message || 'Upload failed', false); return; }
    toast('Uploaded: ' + name, true);
    uploadOk = true;
  } catch(e) {
    toast('Upload error: ' + e.message, false);
  } finally {
    setBusy(false);
  }
  // Refresh AFTER busy is cleared, otherwise api() short-circuits and the
  // list never updates with the newly uploaded dictionary.
  if (uploadOk) {
    await loadDictList();
    refreshSpiffs();
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

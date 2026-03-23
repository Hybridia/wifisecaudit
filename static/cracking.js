// ─── Cracking Tab JavaScript ──────────────────────────────────────────────

let crackPollInterval = null;

// ─── Wordlists ───────────────────────────────────────────────────────────

async function loadWordlists() {
    const wls = await api('/api/wordlists');
    const sel = document.getElementById('crackWordlist');
    const list = document.getElementById('wordlistList');
    if (!wls || wls.length === 0) {
        sel.innerHTML = '<option value="">No wordlists found</option>';
        list.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:12px">No wordlists available. Upload one or decompress rockyou.txt.</div>';
        return;
    }
    sel.innerHTML = wls.filter(w => !w.compressed).map(w =>
        `<option value="${escapeHtml(w.path)}">${escapeHtml(w.name)} (${formatSize(w.size)}) [${w.source}]</option>`
    ).join('');

    list.innerHTML = wls.map(w => `<div class="flex-between" style="padding:4px 8px;border-bottom:1px solid var(--border)">
        <div style="font-size:12px">
            <span style="color:var(--text-primary)">${escapeHtml(w.name)}</span>
            <span style="color:var(--text-muted);margin-left:8px">${formatSize(w.size)}</span>
            <span class="badge ${w.source==='system'?'badge-green':'badge-purple'}" style="margin-left:4px">${w.source}</span>
            ${w.compressed ? '<span class="badge badge-yellow" style="margin-left:4px">compressed</span>' : ''}
        </div>
        <div class="flex gap-8">
            ${w.compressed && w.name.includes('rockyou') ? `<button class="btn btn-sm" onclick="decompressRockyou()">Decompress</button>` : ''}
            ${w.source==='uploaded' ? `<button class="btn btn-sm btn-danger" onclick="deleteWordlist('${escapeHtml(w.name)}')">Delete</button>` : ''}
        </div>
    </div>`).join('');
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes/1048576).toFixed(1) + ' MB';
    return (bytes/1073741824).toFixed(2) + ' GB';
}

async function uploadWordlist() {
    const input = document.getElementById('wordlistUpload');
    if (!input.files.length) return;
    const form = new FormData();
    form.append('file', input.files[0]);
    const r = await fetch('/api/wordlists/upload', {method: 'POST', body: form});
    const data = await r.json();
    if (data.success) { await loadWordlists(); input.value = ''; }
    else { openModal('Upload Error', `<p style="color:var(--accent-red)">${escapeHtml(data.error)}</p>`); }
}

async function deleteWordlist(name) {
    if (!confirm(`Delete wordlist: ${name}?`)) return;
    await api(`/api/wordlists/${encodeURIComponent(name)}`, {method: 'DELETE'});
    await loadWordlists();
}

async function decompressRockyou() {
    const r = await api('/api/wordlists/decompress-rockyou', {method: 'POST'});
    if (r) openModal('Decompress', `<p>${escapeHtml(r.message)}</p>`);
    await loadWordlists();
}

// ─── Cap Files ───────────────────────────────────────────────────────────

async function loadCapFiles() {
    const files = await api('/api/crack/files');
    const tbody = document.querySelector('#capFilesTable tbody');
    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No capture files. Export handshakes first.</td></tr>';
        return;
    }
    tbody.innerHTML = files.map(f => `<tr>
        <td style="font-size:11px">${escapeHtml(f.name)}</td>
        <td>${formatSize(f.size)}</td>
        <td style="font-size:11px;color:var(--text-muted)">${new Date(f.modified).toLocaleString()}</td>
        <td><button class="btn btn-primary btn-sm" onclick="startCrack('${escapeHtml(f.path)}')">Crack</button></td>
    </tr>`).join('');
}

// ─── Cracking ────────────────────────────────────────────────────────────

async function startCrack(capFile) {
    const wordlist = document.getElementById('crackWordlist').value;
    if (!wordlist) { openModal('Error', '<p>Select a wordlist first.</p>'); return; }
    const r = await api('/api/crack/start', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cap_file: capFile, wordlist})});
    if (r && r.success) {
        const panel = document.getElementById('crackProgress');
        const title = panel.querySelector('.card-title');
        panel.style.display = '';
        panel.style.borderColor = 'var(--accent-green)';
        title.textContent = 'Cracking in Progress';
        title.style.color = 'var(--accent-green)';
        document.getElementById('crackStopBtn').style.display = '';
        document.getElementById('crackStopBtn').disabled = false;
        document.getElementById('crackResult').innerHTML = '';
        document.getElementById('crackProgressText').textContent = 'Starting aircrack-ng...';
        startCrackPoll();
    } else { openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.error||'Failed')}</p>`); }
}

async function stopCrack() {
    document.getElementById('crackStopBtn').disabled = true;
    document.getElementById('crackProgressText').textContent = 'Stopping...';
    await api('/api/crack/stop', {method:'POST'});
    setTimeout(async () => {
        const panel = document.getElementById('crackProgress');
        const title = panel.querySelector('.card-title');
        title.textContent = 'Cracking Finished';
        title.style.color = 'var(--accent-yellow)';
        panel.style.borderColor = 'var(--accent-yellow)';
        document.getElementById('crackStopBtn').style.display = 'none';
        document.getElementById('crackProgressText').textContent = '';
        document.getElementById('crackResult').innerHTML = '<span style="color:var(--accent-yellow)">Stopped by user</span>';
        stopCrackPoll();
    }, 500);
}

function startCrackPoll() {
    if (crackPollInterval) return;
    crackPollInterval = setInterval(async () => {
        const s = await api('/api/crack/status');
        if (!s) return;

        if (s.running) {
            document.getElementById('crackProgressText').textContent = s.progress || 'Cracking...';
            document.getElementById('crackResult').innerHTML = '';
            return;
        }

        // Cracking finished — update UI and stop polling
        stopCrackPoll();
        const panel = document.getElementById('crackProgress');
        const title = panel.querySelector('.card-title');
        document.getElementById('crackStopBtn').style.display = 'none';

        const isKeyFound = s.result && !s.result.startsWith('error') && s.result !== 'exhausted' && s.result !== 'stopped';

        if (isKeyFound) {
            title.textContent = 'Key Found';
            title.style.color = 'var(--accent-green)';
            panel.style.borderColor = 'var(--accent-green)';
            document.getElementById('crackProgressText').textContent = 'Cracking complete';
            document.getElementById('crackResult').innerHTML = `<span style="color:var(--accent-green);font-size:18px;font-weight:700">KEY FOUND: ${escapeHtml(s.result)}</span>`;
        } else {
            title.textContent = 'Cracking Finished';
            title.style.color = 'var(--accent-yellow)';
            panel.style.borderColor = 'var(--accent-yellow)';
            document.getElementById('crackProgressText').textContent = '';
            document.getElementById('crackResult').innerHTML = `<span style="color:var(--accent-yellow)">${escapeHtml(s.result || 'No result')}</span>`;
        }
    }, 2000);
}

function stopCrackPoll() {
    if (crackPollInterval) { clearInterval(crackPollInterval); crackPollInterval = null; }
}

// ─── MAC Spoofer ─────────────────────────────────────────────────────────

async function loadCurrentMac() {
    const r = await api('/api/mac/current');
    if (r) document.getElementById('currentMac').textContent = r.mac || 'unknown';
}

async function randomizeMac() {
    document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-yellow)">Changing MAC...</span>';
    const r = await api('/api/mac/change', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({randomize: true})});
    if (r && r.success) {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-green)">${escapeHtml(r.message)}</span>`;
    } else {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed')}</span>`;
    }
    await loadCurrentMac();
}

async function setCustomMac() {
    const mac = document.getElementById('customMacInput').value.trim();
    if (!mac) { document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-red)">Enter a MAC address (e.g. AA:BB:CC:DD:EE:FF)</span>'; return; }
    document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-yellow)">Changing MAC...</span>';
    const r = await api('/api/mac/change', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mac})});
    if (r && r.success) {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-green)">${escapeHtml(r.message)}</span>`;
    } else {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed')}</span>`;
    }
    await loadCurrentMac();
}

async function cloneMac() {
    const mac = document.getElementById('cloneMacInput').value.trim();
    if (!mac) { document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-red)">Enter a MAC to clone from the clients table</span>'; return; }
    document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-yellow)">Cloning MAC...</span>';
    const r = await api('/api/mac/change', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({clone_from: mac})});
    if (r && r.success) {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-green)">${escapeHtml(r.message)}</span>`;
    } else {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed')}</span>`;
    }
    await loadCurrentMac();
}

async function restoreMac() {
    document.getElementById('macResult').innerHTML = '<span style="color:var(--accent-yellow)">Restoring MAC...</span>';
    const r = await api('/api/mac/restore', {method:'POST'});
    if (r && r.success) {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-green)">${escapeHtml(r.message)}</span>`;
    } else {
        document.getElementById('macResult').innerHTML = `<span style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed')}</span>`;
    }
    await loadCurrentMac();
}

// ─── Handshake Validation ────────────────────────────────────────────────

async function validateHandshakes() {
    document.getElementById('validateBtn').disabled = true;
    document.getElementById('validateBtn').textContent = 'Validating...';
    const r = await api('/api/handshake/validate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({})});
    document.getElementById('validateBtn').disabled = false;
    document.getElementById('validateBtn').textContent = 'Validate All';

    const container = document.getElementById('validateResults');
    if (!r || !r.files) {
        container.innerHTML = '<div style="color:var(--text-muted);padding:8px">No capture files found.</div>';
        return;
    }
    if (r.files.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted);padding:8px">No .cap files in data/ directory.</div>';
        return;
    }
    container.innerHTML = r.files.map(f => {
        const name = f.file.split('/').pop();
        const icon = f.valid ? '<span style="color:var(--accent-green)">&#10003;</span>' : '<span style="color:var(--accent-red)">&#10007;</span>';
        const nets = (f.networks || []).map(n => `${escapeHtml(n.ssid)} (${n.handshake_count} hs)`).join(', ');
        const detail = f.valid ? (nets || `${f.eapol_frames||'?'} EAPOL frames`) : (f.error || 'No valid handshake');
        return `<div style="padding:4px 8px;border-bottom:1px solid var(--border);font-size:12px">
            ${icon} <span style="color:var(--text-primary)">${escapeHtml(name)}</span>
            <span style="color:var(--text-muted);margin-left:8px">${escapeHtml(detail)}</span>
            <span class="badge ${f.valid?'badge-green':'badge-red'}" style="margin-left:4px;font-size:10px">${f.method||''}</span>
        </div>`;
    }).join('');
}

// ─── Init ────────────────────────────────────────────────────────────────

function initCrackingTab() {
    loadWordlists();
    loadCapFiles();
    loadCurrentMac();
    // Check if crack is already running
    api('/api/crack/status').then(s => {
        if (s && s.running) {
            document.getElementById('crackProgress').style.display = '';
            document.getElementById('crackStopBtn').disabled = false;
            startCrackPoll();
        }
    });
}

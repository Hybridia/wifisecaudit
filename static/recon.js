// ─── Recon Tab JavaScript ─────────────────────────────────────────────────

let nmapPollInterval = null;
let wpsPollInterval = null;
let wpsScanPollInterval = null;
let idsPollInterval = null;
let wpa3PollInterval = null;

// ─── Dual Interface ──────────────────────────────────────────────────────

async function dualAutoDetect() {
    const r = await api('/api/dual/auto', {method:'POST'});
    if (r && r.success) {
        openModal('Dual Adapter', `<p style="color:var(--accent-green)">${escapeHtml(r.message)}</p>`);
    } else {
        openModal('Dual Adapter', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed — need 2 WiFi adapters')}</p>`);
    }
    loadDualStatus();
}

async function dualManualAssign() {
    const primary = document.getElementById('dualPrimary').value;
    const secondary = document.getElementById('dualSecondary').value;
    if (!primary || !secondary) { openModal('Error', '<p>Select both interfaces</p>'); return; }
    const r = await api('/api/dual/assign', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({primary, secondary})});
    if (r && r.success) loadDualStatus();
    else openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||'Failed')}</p>`);
}

async function dualEnableMonitor() {
    const r = await api('/api/dual/monitor', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({enable: true})});
    if (r && r.success) {
        document.getElementById('dualMonBtn').style.display = 'none';
        document.getElementById('dualMonOffBtn').style.display = '';
    }
    loadDualStatus();
}

async function dualDisableMonitor() {
    const r = await api('/api/dual/monitor', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({enable: false})});
    document.getElementById('dualMonBtn').style.display = '';
    document.getElementById('dualMonOffBtn').style.display = 'none';
    loadDualStatus();
}

async function loadDualStatus() {
    const data = await api('/api/dual/detect');
    if (!data) return;

    const el = document.getElementById('dualStatus');
    if (data.enabled) {
        el.innerHTML = `<span class="badge badge-green">Active</span> ` +
            `Primary: <span style="color:var(--accent-cyan)">${escapeHtml(data.primary_mon||data.primary)}</span> (capture) &nbsp; ` +
            `Secondary: <span style="color:var(--accent-orange)">${escapeHtml(data.secondary_mon||data.secondary)}</span> (inject)`;
    } else {
        el.innerHTML = '<span style="color:var(--text-muted)">Not configured — click Auto-Detect or assign manually</span>';
    }

    // Populate selects
    const ifaces = data.interfaces || [];
    for (const selId of ['dualPrimary', 'dualSecondary']) {
        const sel = document.getElementById(selId);
        const current = sel.value;
        sel.innerHTML = `<option value="">${selId === 'dualPrimary' ? 'Primary (capture)' : 'Secondary (inject)'}</option>` +
            ifaces.map(i => `<option value="${escapeHtml(i.name)}" ${i.name===current?'selected':''}>${escapeHtml(i.name)} (${escapeHtml(i.driver)})</option>`).join('');
    }
}

// ─── WPA3-SAE Attack ─────────────────────────────────────────────────────

async function startWpa3Attack() {
    const bssid = document.getElementById('wpa3Bssid').value.trim();
    const channel = parseInt(document.getElementById('wpa3Channel').value) || null;
    const method = document.getElementById('wpa3Method').value;
    if (!bssid) { openModal('Error', '<p>Enter target BSSID</p>'); return; }

    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/wpa3/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({bssid, channel, method, interface: iface})});

    if (r && r.success) {
        document.getElementById('wpa3StartBtn').style.display = 'none';
        document.getElementById('wpa3StopBtn').style.display = '';
        startWpa3Poll();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||r?.error||'Failed')}</p>`);
    }
}

async function stopWpa3Attack() {
    await api('/api/wpa3/stop', {method:'POST'});
    document.getElementById('wpa3StartBtn').style.display = '';
    document.getElementById('wpa3StopBtn').style.display = 'none';
    stopWpa3Poll();
}

function startWpa3Poll() {
    if (wpa3PollInterval) return;
    wpa3PollInterval = setInterval(async () => {
        const s = await api('/api/wpa3/status');
        if (!s) return;
        document.getElementById('wpa3Progress').textContent = s.progress || '';
        if (s.result) {
            let html = '';
            if (s.result.message) html = `<span style="color:var(--accent-green)">${escapeHtml(s.result.message)}</span>`;
            if (s.result.cap_file) html += `<br><span style="font-size:11px;color:var(--text-muted)">File: ${escapeHtml(s.result.cap_file)}</span>`;
            if (s.result.hash_file) html += `<br><span style="font-size:11px;color:var(--text-muted)">Hash: ${escapeHtml(s.result.hash_file)}</span>`;
            if (s.result.error) html = `<span style="color:var(--accent-yellow)">${escapeHtml(s.result.error)}</span>`;
            document.getElementById('wpa3Result').innerHTML = html;
        }
        if (!s.running) {
            document.getElementById('wpa3StartBtn').style.display = '';
            document.getElementById('wpa3StopBtn').style.display = 'none';
            stopWpa3Poll();
        }
    }, 3000);
}

function stopWpa3Poll() {
    if (wpa3PollInterval) { clearInterval(wpa3PollInterval); wpa3PollInterval = null; }
}

async function scanDragonblood() {
    const bssid = document.getElementById('wpa3Bssid').value.trim();
    if (!bssid) { openModal('Error', '<p>Enter target BSSID</p>'); return; }

    const channel = parseInt(document.getElementById('wpa3Channel').value) || null;
    const iface = document.getElementById('wifiInterface').value;

    document.getElementById('dragonbloodReport').style.display = '';
    document.getElementById('dragonbloodReport').innerHTML = '<div style="color:var(--text-muted);font-size:12px">Scanning...</div>';

    const r = await api('/api/wpa3/dragonblood', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({bssid, channel, interface: iface})});

    if (!r) {
        document.getElementById('dragonbloodReport').innerHTML = '<div style="color:var(--accent-red)">Scan failed</div>';
        return;
    }

    const riskColors = {high: 'var(--accent-red)', medium: 'var(--accent-orange)', low: 'var(--accent-yellow)', none: 'var(--accent-green)'};
    let html = `<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px">
        <div class="flex-between mb-8">
            <span style="font-weight:600">Dragonblood Report: ${escapeHtml(bssid)}</span>
            <span class="badge" style="background:${riskColors[r.risk_level]||'var(--text-muted)'}20;color:${riskColors[r.risk_level]||'var(--text-muted)'}">${(r.risk_level||'unknown').toUpperCase()} RISK</span>
        </div>`;

    if (r.transition_mode) html += `<div style="font-size:12px;color:var(--accent-orange);margin-bottom:4px">&#9888; Transition mode (WPA2+WPA3) — downgrade attack viable</div>`;
    if (r.pmf_required) html += `<div style="font-size:12px;color:var(--accent-green);margin-bottom:4px">&#128274; PMF required — deauth attacks blocked</div>`;
    else html += `<div style="font-size:12px;color:var(--accent-yellow);margin-bottom:4px">&#9888; PMF not required — deauth attacks possible</div>`;

    if (r.vulnerabilities && r.vulnerabilities.length > 0) {
        html += '<div style="font-size:11px;margin-top:4px">';
        r.vulnerabilities.forEach(v => { html += `<div style="color:var(--accent-red);margin-bottom:2px">&#8226; ${escapeHtml(v)}</div>`; });
        html += '</div>';
    }
    if (r.recommendations && r.recommendations.length > 0) {
        html += '<div style="font-size:11px;margin-top:4px;color:var(--text-secondary)">';
        r.recommendations.forEach(v => { html += `<div>&#8594; ${escapeHtml(v)}</div>`; });
        html += '</div>';
    }
    html += '</div>';
    document.getElementById('dragonbloodReport').innerHTML = html;
}

// ─── Nmap ────────────────────────────────────────────────────────────────

async function startNmapScan() {
    const target = document.getElementById('nmapTarget').value.trim();
    const scanType = document.getElementById('nmapScanType').value;
    if (!target) { openModal('Error', '<p>Enter a target IP or range.</p>'); return; }

    const r = await api('/api/nmap/scan', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({target, scan_type: scanType})});

    if (r && r.success) {
        document.getElementById('nmapStartBtn').disabled = true;
        document.getElementById('nmapStartBtn').textContent = 'Scanning...';
        document.getElementById('nmapStopBtn').style.display = '';
        startNmapPoll();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.error||r?.message||'Failed')}</p>`);
    }
}

async function stopNmapScan() {
    await api('/api/nmap/stop', {method:'POST'});
    nmapScanFinished();
}

function nmapScanFinished() {
    document.getElementById('nmapStartBtn').disabled = false;
    document.getElementById('nmapStartBtn').textContent = 'Scan';
    document.getElementById('nmapStopBtn').style.display = 'none';
    stopNmapPoll();
}

function startNmapPoll() {
    if (nmapPollInterval) return;
    nmapPollInterval = setInterval(async () => {
        const data = await api('/api/nmap/results');
        if (!data) return;
        if (!data.running) nmapScanFinished();
        if (data.results) renderNmapResults(data.results);
    }, 3000);
}

function stopNmapPoll() {
    if (nmapPollInterval) { clearInterval(nmapPollInterval); nmapPollInterval = null; }
}

function renderNmapResults(results) {
    const container = document.getElementById('nmapResults');
    if (results.error) {
        container.innerHTML = `<div style="color:var(--accent-red);padding:12px">${escapeHtml(results.error)}</div>`;
        return;
    }
    const hosts = results.hosts || [];
    if (hosts.length === 0) {
        container.innerHTML = '<div style="padding:12px;color:var(--text-muted)">No hosts found.</div>';
        return;
    }
    let html = '';
    for (const host of hosts) {
        const addrs = host.addresses.map(a => a.addr).join(', ');
        const names = host.hostnames.length > 0 ? ` (${host.hostnames.join(', ')})` : '';
        const os = host.os.length > 0 ? `<div style="font-size:11px;color:var(--accent-purple);margin-top:2px">OS: ${escapeHtml(host.os[0].name)} (${host.os[0].accuracy}%)</div>` : '';
        html += `<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:8px">
            <div class="flex-between">
                <span style="font-weight:600;color:var(--accent-cyan)">${escapeHtml(addrs)}${escapeHtml(names)}</span>
                <span class="badge ${host.status==='up'?'badge-green':'badge-red'}">${host.status}</span>
            </div>${os}`;
        if (host.ports.length > 0) {
            html += `<table style="margin-top:8px;font-size:11px"><thead><tr>
                <th style="padding:4px 8px">Port</th><th style="padding:4px 8px">State</th><th style="padding:4px 8px">Service</th><th style="padding:4px 8px">Version</th>
            </tr></thead><tbody>`;
            for (const p of host.ports) {
                const stateColor = p.state === 'open' ? 'var(--accent-green)' : p.state === 'filtered' ? 'var(--accent-yellow)' : 'var(--text-muted)';
                html += `<tr><td style="padding:3px 8px">${p.port}/${p.protocol}</td>
                    <td style="padding:3px 8px;color:${stateColor}">${p.state}</td>
                    <td style="padding:3px 8px">${escapeHtml(p.service)}</td>
                    <td style="padding:3px 8px;color:var(--text-secondary)">${escapeHtml(p.version||'')}</td></tr>`;
            }
            html += '</tbody></table>';
        }
        html += '</div>';
    }
    container.innerHTML = html;
}

// ─── WPS Scanner (wash) ─────────────────────────────────────────────────

async function startWpsScan() {
    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/wps/scan', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({interface: iface, duration: 30})});
    if (r && r.success) {
        document.getElementById('wpsScanBtn').disabled = true;
        document.getElementById('wpsScanBtn').textContent = 'Scanning...';
        document.getElementById('wpsScanStopBtn').style.display = '';
        startWpsScanPoll();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.error||r?.message||'Failed')}</p>`);
    }
}

async function stopWpsScan() {
    await api('/api/wps/scan/stop', {method:'POST'});
    wpsScanFinished();
}

function wpsScanFinished() {
    document.getElementById('wpsScanBtn').disabled = false;
    document.getElementById('wpsScanBtn').textContent = 'Scan for WPS';
    document.getElementById('wpsScanStopBtn').style.display = 'none';
    stopWpsScanPoll();
}

function startWpsScanPoll() {
    if (wpsScanPollInterval) return;
    wpsScanPollInterval = setInterval(async () => {
        const data = await api('/api/wps/scan/results');
        if (!data) return;
        if (!data.running) wpsScanFinished();
        renderWpsNetworks(data.networks || []);
    }, 3000);
}

function stopWpsScanPoll() {
    if (wpsScanPollInterval) { clearInterval(wpsScanPollInterval); wpsScanPollInterval = null; }
}

function renderWpsNetworks(networks) {
    const tbody = document.querySelector('#wpsNetworksTable tbody');
    if (networks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted)">No WPS networks found</td></tr>';
        return;
    }
    tbody.innerHTML = networks.map(n => {
        const lockBadge = n.locked ? '<span class="badge badge-red">Locked</span>' : '<span class="badge badge-green">Open</span>';
        return `<tr>
            <td>${escapeHtml(n.ssid)}</td>
            <td style="font-size:11px;color:var(--text-muted)">${escapeHtml(n.bssid)}</td>
            <td>${n.channel}</td>
            <td>${n.signal} dBm</td>
            <td>${n.wps_version}</td>
            <td>${lockBadge}</td>
            <td>
                <button class="btn btn-sm" onclick="fillWpsTarget('${escapeHtml(n.bssid)}','${n.channel}')">Pixie</button>
                <button class="btn btn-sm" onclick="fillWpsTargetBrute('${escapeHtml(n.bssid)}','${n.channel}')">Brute</button>
            </td>
        </tr>`;
    }).join('');
}

function fillWpsTarget(bssid, channel) {
    document.getElementById('wpsBssid').value = bssid;
    document.getElementById('wpsChannel').value = channel;
    document.getElementById('wpsPixieDust').checked = true;
}

function fillWpsTargetBrute(bssid, channel) {
    document.getElementById('wpsBssid').value = bssid;
    document.getElementById('wpsChannel').value = channel;
    document.getElementById('wpsPixieDust').checked = false;
}

// ─── WPS Attack ──────────────────────────────────────────────────────────

async function startWpsAttack() {
    const bssid = document.getElementById('wpsBssid').value.trim();
    const tool = document.getElementById('wpsTool').value;
    const channel = parseInt(document.getElementById('wpsChannel').value) || null;
    const pixie_dust = document.getElementById('wpsPixieDust').checked;
    if (!bssid) { openModal('Error', '<p>Enter a target BSSID.</p>'); return; }

    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/wps/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({bssid, tool, channel, interface: iface, pixie_dust})});

    if (r && r.success) {
        document.getElementById('wpsStartBtn').style.display = 'none';
        document.getElementById('wpsStopBtn').style.display = '';
        startWpsPoll();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.error||r?.message||'Failed')}</p>`);
    }
}

async function stopWpsAttack() {
    await api('/api/wps/stop', {method:'POST'});
    document.getElementById('wpsStartBtn').style.display = '';
    document.getElementById('wpsStopBtn').style.display = 'none';
    stopWpsPoll();
}

function startWpsPoll() {
    if (wpsPollInterval) return;
    wpsPollInterval = setInterval(async () => {
        const s = await api('/api/wps/status');
        if (!s) return;
        document.getElementById('wpsProgress').textContent = s.progress || '';
        if (s.result) {
            let html = '';
            if (s.result.pin) html += `<span style="color:var(--accent-green)">PIN: ${escapeHtml(s.result.pin)}</span> `;
            if (s.result.password) html += `<span style="color:var(--accent-cyan)">Password: ${escapeHtml(s.result.password)}</span>`;
            if (s.result.error) html = `<span style="color:var(--accent-yellow)">${escapeHtml(s.result.error)}</span>`;
            document.getElementById('wpsResult').innerHTML = html;
        }
        if (!s.running) {
            document.getElementById('wpsStartBtn').style.display = '';
            document.getElementById('wpsStopBtn').style.display = 'none';
            stopWpsPoll();
        }
    }, 3000);
}

function stopWpsPoll() {
    if (wpsPollInterval) { clearInterval(wpsPollInterval); wpsPollInterval = null; }
}

// ─── Signal Strength Filter ──────────────────────────────────────────────

function applySignalFilter() {
    const minSignal = parseInt(document.getElementById('signalFilter').value) || -100;
    document.getElementById('signalFilterValue').textContent = minSignal <= -100 ? 'All' : minSignal + ' dBm';
    window._minSignalFilter = minSignal;
    // Re-render networks immediately
    loadWifiNetworks();
}

// ─── Attack Monitor / IDS ────────────────────────────────────────────────

async function startIDS() {
    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/ids/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({interface: iface})});
    if (r && r.success) {
        document.getElementById('idsStartBtn').style.display = 'none';
        document.getElementById('idsStopBtn').style.display = '';
        document.getElementById('idsStatus').innerHTML = '<span style="color:var(--accent-green)">Monitoring</span>';
        startIdsPoll();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||r?.error||'Failed')}</p>`);
    }
}

async function stopIDS() {
    await api('/api/ids/stop', {method:'POST'});
    document.getElementById('idsStartBtn').style.display = '';
    document.getElementById('idsStopBtn').style.display = 'none';
    document.getElementById('idsStatus').innerHTML = '<span style="color:var(--text-muted)">Off</span>';
    stopIdsPoll();
}

async function clearIDSAlerts() {
    await api('/api/ids/clear', {method:'POST'});
    document.getElementById('idsAlerts').innerHTML = '<div style="padding:8px;color:var(--text-muted)">No alerts</div>';
    document.getElementById('idsStats').innerHTML = '';
}

function startIdsPoll() {
    if (idsPollInterval) return;
    idsPollInterval = setInterval(loadIDSStatus, 5000);
    loadIDSStatus();
}

function stopIdsPoll() {
    if (idsPollInterval) { clearInterval(idsPollInterval); idsPollInterval = null; }
}

async function loadIDSStatus() {
    const data = await api('/api/ids/status');
    if (!data) return;

    if (!data.running) {
        document.getElementById('idsStartBtn').style.display = '';
        document.getElementById('idsStopBtn').style.display = 'none';
        document.getElementById('idsStatus').innerHTML = '<span style="color:var(--text-muted)">Off</span>';
        stopIdsPoll();
    }

    // Stats
    const s = data.stats || {};
    document.getElementById('idsStats').innerHTML = `
        <span style="margin-right:12px">Deauth: <span style="color:var(--accent-red)">${s.deauth_frames||0}</span></span>
        <span style="margin-right:12px">Disassoc: <span style="color:var(--accent-yellow)">${s.disassoc_frames||0}</span></span>
        <span>Suspicious APs: <span style="color:var(--accent-orange)">${s.suspicious_aps||0}</span></span>`;

    // Alerts
    const alerts = data.alerts || [];
    const container = document.getElementById('idsAlerts');
    if (alerts.length === 0) {
        container.innerHTML = '<div style="padding:8px;color:var(--text-muted)">No alerts — network looks clean</div>';
        return;
    }
    container.innerHTML = alerts.slice().reverse().map(a => {
        const colors = {critical: 'var(--accent-red)', high: 'var(--accent-orange)', medium: 'var(--accent-yellow)', low: 'var(--text-muted)'};
        const icons = {deauth_flood: '&#9888;', disassoc_flood: '&#9888;', evil_twin: '&#128279;'};
        return `<div class="event-entry" style="border-left-color:${colors[a.severity]||'var(--border)'}">
            <span class="event-time">${new Date(a.timestamp).toLocaleTimeString()}</span>
            <span style="color:${colors[a.severity]};min-width:60px;font-weight:600">${icons[a.type]||''} ${a.severity.toUpperCase()}</span>
            <span class="event-msg">${escapeHtml(a.details)}</span>
        </div>`;
    }).join('');
}

// ─── Report ──────────────────────────────────────────────────────────────

async function generateReport() {
    document.getElementById('reportBtn').disabled = true;
    document.getElementById('reportBtn').textContent = 'Generating...';
    const r = await api('/api/report/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({})});
    document.getElementById('reportBtn').disabled = false;
    document.getElementById('reportBtn').textContent = 'Generate PDF Report';
    if (r && r.success) {
        openModal('Report Generated', `<p>Report saved to:</p><code style="font-size:12px;color:var(--accent-green)">${escapeHtml(r.file)}</code>`);
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.error||'Failed')}</p>`);
    }
}

// ─── Init ────────────────────────────────────────────────────────────────

function initReconTab() {
    loadDualStatus();
    // Check WPA3 running state
    api('/api/wpa3/status').then(s => {
        if (s && s.running) {
            document.getElementById('wpa3StartBtn').style.display = 'none';
            document.getElementById('wpa3StopBtn').style.display = '';
            startWpa3Poll();
        }
    });
    // Check running states
    api('/api/nmap/results').then(data => {
        if (data && data.running) {
            document.getElementById('nmapStartBtn').disabled = true;
            document.getElementById('nmapStartBtn').textContent = 'Scanning...';
            document.getElementById('nmapStopBtn').style.display = '';
            startNmapPoll();
        }
        if (data && data.results) renderNmapResults(data.results);
    });
    api('/api/wps/status').then(s => {
        if (s && s.running) {
            document.getElementById('wpsStartBtn').style.display = 'none';
            document.getElementById('wpsStopBtn').style.display = '';
            startWpsPoll();
        }
    });
    api('/api/wps/scan/results').then(data => {
        if (data && data.running) {
            document.getElementById('wpsScanBtn').disabled = true;
            document.getElementById('wpsScanBtn').textContent = 'Scanning...';
            document.getElementById('wpsScanStopBtn').style.display = '';
            startWpsScanPoll();
        }
        if (data && data.networks) renderWpsNetworks(data.networks);
    });
    api('/api/ids/status').then(data => {
        if (data && data.running) {
            document.getElementById('idsStartBtn').style.display = 'none';
            document.getElementById('idsStopBtn').style.display = '';
            document.getElementById('idsStatus').innerHTML = '<span style="color:var(--accent-green)">Monitoring</span>';
            startIdsPoll();
        }
    });
}

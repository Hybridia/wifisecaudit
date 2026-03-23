// ─── Evil Twin Tab JavaScript ─────────────────────────────────────────────

let etPollInterval = null;
let arpPollInterval = null;
let trafficPollInterval = null;
let credsPollInterval = null;

// ─── Evil Twin ───────────────────────────────────────────────────────────

async function startEvilTwin() {
    const ssid = document.getElementById('etSsid').value.trim();
    const channel = parseInt(document.getElementById('etChannel').value) || 6;
    const captive = document.getElementById('etCaptive').checked;
    const template = document.getElementById('etTemplate').value;
    const encryption = document.getElementById('etEncryption').value;
    const wpa_passphrase = document.getElementById('etPassphrase').value.trim();

    if (!ssid) { openModal('Error', '<p>Enter an SSID.</p>'); return; }
    if (encryption === 'wpa2' && wpa_passphrase.length < 8) { openModal('Error', '<p>WPA2 passphrase must be at least 8 characters.</p>'); return; }

    const r = await api('/api/eviltwin/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ssid, channel, captive, template, encryption, wpa_passphrase})});

    if (r && r.success) {
        document.getElementById('etStartBtn').style.display = 'none';
        document.getElementById('etStopBtn').style.display = '';
        document.getElementById('etStatus').innerHTML = '<span style="color:var(--accent-green)">AP Active</span>';
        startEtPoll();
        if (captive) startCredsPoll();
        updateModeIndicator();
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||r?.error||'Failed')}</p>`);
    }
}

async function stopEvilTwin() {
    await api('/api/eviltwin/stop', {method:'POST'});
    document.getElementById('etStartBtn').style.display = '';
    document.getElementById('etStopBtn').style.display = 'none';
    document.getElementById('etStatus').innerHTML = '<span style="color:var(--text-muted)">Inactive</span>';
    stopEtPoll();
    stopCredsPoll();
    updateModeIndicator();
}

function startEtPoll() {
    if (etPollInterval) return;
    etPollInterval = setInterval(async () => {
        const status = await api('/api/eviltwin/status');
        if (status && !status.running) { stopEvilTwin(); return; }

        const clients = await api('/api/eviltwin/clients');
        const tbody = document.querySelector('#etClientsTable tbody');
        if (clients && clients.length > 0) {
            tbody.innerHTML = clients.map(c => `<tr>
                <td>${escapeHtml(c.ip)}</td>
                <td style="font-size:11px">${escapeHtml(c.mac)}</td>
                <td><button class="btn btn-sm" onclick="setArpTarget('${escapeHtml(c.ip)}','192.168.4.1')">Target</button></td>
            </tr>`).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">No clients connected</td></tr>';
        }
    }, 5000);
}

function stopEtPoll() {
    if (etPollInterval) { clearInterval(etPollInterval); etPollInterval = null; }
}

// ─── Captive Portal Credentials ──────────────────────────────────────────

function startCredsPoll() {
    if (credsPollInterval) return;
    credsPollInterval = setInterval(loadCapturedCredentials, 5000);
}

function stopCredsPoll() {
    if (credsPollInterval) { clearInterval(credsPollInterval); credsPollInterval = null; }
}

async function loadCapturedCredentials() {
    const creds = await api('/api/captive/credentials');
    const tbody = document.querySelector('#credsTable tbody');
    if (!creds || creds.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No credentials captured</td></tr>';
        return;
    }
    tbody.innerHTML = creds.map(c => `<tr>
        <td style="font-size:11px;color:var(--text-muted)">${new Date(c.timestamp).toLocaleTimeString()}</td>
        <td style="font-size:11px">${escapeHtml(c.ip)}</td>
        <td style="color:var(--accent-cyan)">${escapeHtml(c.username)}</td>
        <td style="color:var(--accent-green)">${escapeHtml(c.password)}</td>
    </tr>`).join('');
}

// ─── Network Host Discovery ──────────────────────────────────────────────

async function discoverHosts() {
    const btn = document.getElementById('hostScanBtn');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/hosts/discover', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({interface: iface})});
    btn.disabled = false;
    btn.textContent = 'Discover Hosts';

    if (!r) { openModal('Error', '<p>Host discovery failed</p>'); return; }
    if (r.error) { openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r.error)}</p>`); return; }

    // Show gateway info
    const gwInfo = document.getElementById('hostGatewayInfo');
    if (r.gateway) {
        gwInfo.style.display = '';
        gwInfo.innerHTML = `<span style="color:var(--text-secondary)">Gateway:</span> <span style="color:var(--accent-cyan)">${escapeHtml(r.gateway)}</span> &nbsp; <span style="color:var(--text-secondary)">Subnet:</span> <span style="color:var(--accent-cyan)">${escapeHtml(r.subnet)}</span>`;
        // Auto-fill gateway for ARP spoof
        document.getElementById('arpGateway').value = r.gateway;
    }

    const tbody = document.querySelector('#hostsTable tbody');
    const hosts = r.hosts || [];
    if (hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No hosts found. Are you connected to a network?</td></tr>';
        return;
    }
    tbody.innerHTML = hosts.map(h => {
        const isGateway = h.ip === r.gateway;
        return `<tr>
            <td style="color:${isGateway ? 'var(--accent-yellow)' : 'var(--text-primary)'}">${escapeHtml(h.ip)}${isGateway ? ' <span style="font-size:10px">(gateway)</span>' : ''}</td>
            <td style="font-size:11px;color:var(--text-muted)">${escapeHtml(h.mac)}</td>
            <td style="font-size:11px">${escapeHtml(h.vendor)}</td>
            <td>${isGateway ? '' : `<button class="btn btn-sm" onclick="setArpTarget('${escapeHtml(h.ip)}','${escapeHtml(r.gateway||'')}')">Target</button>`}</td>
        </tr>`;
    }).join('');
}

function setArpTarget(targetIp, gatewayIp) {
    document.getElementById('arpTarget').value = targetIp;
    if (gatewayIp) document.getElementById('arpGateway').value = gatewayIp;
}

// ─── ARP Spoof ───────────────────────────────────────────────────────────

async function startArpSpoof() {
    const target = document.getElementById('arpTarget').value.trim();
    const gateway = document.getElementById('arpGateway').value.trim();
    if (!target || !gateway) { openModal('Error', '<p>Enter target IP and gateway IP.</p>'); return; }

    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/arpspoof/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({target_ip: target, gateway_ip: gateway, interface: iface})});

    if (r && r.success) {
        document.getElementById('arpStartBtn').style.display = 'none';
        document.getElementById('arpStopBtn').style.display = '';
        document.getElementById('arpStatus').innerHTML = '<span style="color:var(--accent-green)">Active</span>';
    } else {
        openModal('Error', `<p style="color:var(--accent-red)">${escapeHtml(r?.message||r?.error||'Failed')}</p>`);
    }
}

async function stopArpSpoof() {
    await api('/api/arpspoof/stop', {method:'POST'});
    document.getElementById('arpStartBtn').style.display = '';
    document.getElementById('arpStopBtn').style.display = 'none';
    document.getElementById('arpStatus').innerHTML = '<span style="color:var(--text-muted)">Inactive</span>';
}

// ─── Traffic Sniffer ─────────────────────────────────────────────────────

async function startTraffic() {
    const iface = document.getElementById('wifiInterface').value;
    const r = await api('/api/traffic/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({interface: iface})});
    if (r && r.success) {
        document.getElementById('trafficStartBtn').style.display = 'none';
        document.getElementById('trafficStopBtn').style.display = '';
        startTrafficPoll();
    }
}

async function stopTraffic() {
    await api('/api/traffic/stop', {method:'POST'});
    document.getElementById('trafficStartBtn').style.display = '';
    document.getElementById('trafficStopBtn').style.display = 'none';
    stopTrafficPoll();
}

function startTrafficPoll() {
    if (trafficPollInterval) return;
    trafficPollInterval = setInterval(loadTrafficData, 3000);
}

function stopTrafficPoll() {
    if (trafficPollInterval) { clearInterval(trafficPollInterval); trafficPollInterval = null; }
}

async function loadTrafficData() {
    const data = await api('/api/traffic/captured');
    if (!data) return;

    // URLs
    const urlTbody = document.querySelector('#trafficUrlTable tbody');
    if (data.urls && data.urls.length > 0) {
        urlTbody.innerHTML = data.urls.slice(-50).reverse().map(u => `<tr>
            <td style="font-size:11px">${escapeHtml(u.src)}</td>
            <td style="font-size:11px">${escapeHtml(u.method||'GET')}</td>
            <td style="font-size:11px;color:var(--accent-cyan)">${escapeHtml(u.host)}${escapeHtml(u.uri)}</td>
        </tr>`).join('');
    }

    // Cookies
    const cookieTbody = document.querySelector('#trafficCookieTable tbody');
    if (data.cookies && data.cookies.length > 0) {
        cookieTbody.innerHTML = data.cookies.slice(-20).reverse().map(c => `<tr>
            <td style="font-size:11px">${escapeHtml(c.host)}</td>
            <td style="font-size:10px;word-break:break-all;max-width:400px">${escapeHtml(c.cookie)}</td>
        </tr>`).join('');
    }
}

// ─── Mode Indicator ──────────────────────────────────────────────────────

async function updateModeIndicator() {
    const s = await api('/api/eviltwin/status');
    const el = document.getElementById('etModeIndicator');
    if (s) {
        const mode = s.mode || 'managed';
        const colors = {managed: 'var(--text-muted)', monitor: 'var(--accent-green)', ap: 'var(--accent-orange)'};
        el.innerHTML = `<span style="color:${colors[mode]||'var(--text-muted)'}">${mode.toUpperCase()}</span>`;
    }
}

// ─── Init ────────────────────────────────────────────────────────────────

function initEvilTwinTab() {
    updateModeIndicator();
    // Check if ET is already running
    api('/api/eviltwin/status').then(s => {
        if (s && s.running) {
            document.getElementById('etStartBtn').style.display = 'none';
            document.getElementById('etStopBtn').style.display = '';
            document.getElementById('etStatus').innerHTML = '<span style="color:var(--accent-green)">AP Active</span>';
            startEtPoll();
            if (s.captive) startCredsPoll();
        }
    });
    api('/api/arpspoof/status').then(s => {
        if (s && s.running) {
            document.getElementById('arpStartBtn').style.display = 'none';
            document.getElementById('arpStopBtn').style.display = '';
            document.getElementById('arpStatus').innerHTML = '<span style="color:var(--accent-green)">Active</span>';
        }
    });
    loadCapturedCredentials();
}

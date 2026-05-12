const COLORS = ['#00b7ff','#19c37d','#ffb020','#ff5d73','#a78bfa','#4dd4ac','#7cc8ff','#ffd166','#ff8fab','#7ee081'];
let charts = {};
let liveAlertsCache = [];
let liveCurrentPage = 1;
let livePageSize = 100;
const LIVE_FETCH_LIMIT = 1000;

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cybersec-theme', theme);
    document.getElementById('theme-toggle').textContent = theme === 'light' ? '🌙 Mode sombre' : '☀️ Mode clair';
    Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--text').trim();
    Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
    fetchAnalytics();
}
function toggleTheme() { applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light'); }
applyTheme(localStorage.getItem('cybersec-theme') || 'dark');

Chart.defaults.font.family = 'Inter, Arial, sans-serif';
function colors(n) { return Array.from({length:n}, (_, i) => COLORS[i % COLORS.length]); }
function destroyChart(id) { if (charts[id]) charts[id].destroy(); }
function switchView(viewId, btnElement) { document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active')); document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active')); document.getElementById(viewId).classList.add('active'); if (btnElement) btnElement.classList.add('active'); }
function openIp(ip) { document.getElementById('ip-search-input').value = ip; switchView('ip-view', document.querySelectorAll('.nav-btn')[2]); fetchIpDetail(ip); }
function searchIp() { const ip = document.getElementById('ip-search-input').value.trim(); if (ip) fetchIpDetail(ip); }
function badgeClass(type) { const t = (type || '').toUpperCase(); if (t.includes('SQL') || t.includes('XSS') || t.includes('CMD')) return 'sql'; if (t.includes('NMAP') || t.includes('NIKTO') || t.includes('SCAN')) return 'scan'; if (t.includes('BLOCKED') || t.includes('LOGIN') || t.includes('BRUTE')) return 'brute'; if (t.includes('EXFIL')) return 'exfil'; return 'default'; }
function riskBadge(level) { const l = (level || 'LOW').toUpperCase(); return `<span class="risk ${l}">${l}</span>`; }
function num(v) { return Number(v || 0); }
function esc(s) { return String(s ?? '-').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function formatDateTime(value) {
    if (!value || value === '-') return '-';
    const d = new Date(value);
    if (isNaN(d.getTime())) return value;
    return d.toLocaleString('fr-FR', {
        year:'numeric', month:'2-digit', day:'2-digit',
        hour:'2-digit', minute:'2-digit', second:'2-digit'
    });
}
function relationLevel(score) {
    const s = num(score);
    if (s >= 80) return 'Critique';
    if (s >= 50) return 'Élevé';
    if (s >= 20) return 'Moyen';
    return 'Faible';
}
function relationTypesText(r) {
    const types = [
        {name:'SQLi', value:num(r.sqli_count)},
        {name:'Scan', value:num(r.scan_count)},
        {name:'XSS', value:num(r.xss_count)},
        {name:'Exfiltration', value:num(r.exfiltration_count)},
        {name:'Accès fichiers', value:num(r.file_attack_count)},
        {name:'Admin probing', value:num(r.admin_probe_count)},
        {name:'Fichiers sensibles', value:num(r.sensitive_file_count)},
        {name:'Command injection', value:num(r.command_injection_count)}
    ].filter(x => x.value > 0);
    return types.length ? types.map(x => `${x.name}=${x.value}`).join(' | ') : '-';
}

function makeBar(id, labels, values, horizontal=true) { destroyChart(id); charts[id] = new Chart(document.getElementById(id), { type: 'bar', data: { labels, datasets: [{ data: values, backgroundColor: colors(labels.length), borderColor: 'rgba(255,255,255,0.18)', borderWidth: 1, borderRadius: 8 }] }, options: { indexAxis: horizontal ? 'y' : 'x', maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { color: 'rgba(128,128,128,0.15)' } }, y: { grid: { color: 'rgba(128,128,128,0.08)' } } } } }); }
function makeDoughnut(id, labels, values) { destroyChart(id); charts[id] = new Chart(document.getElementById(id), { type: 'doughnut', data: { labels, datasets: [{ data: values, backgroundColor: colors(labels.length), borderColor: 'rgba(255,255,255,0.18)', borderWidth: 2 }] }, options: { maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, padding: 16 } } } } }); }
function makeLine(id, labels, datasets) {
    destroyChart(id);
    charts[id] = new Chart(document.getElementById(id), {
        type: 'line',
        data: { labels, datasets },
        options: {
            maintainAspectRatio: false,
            responsive: true,
            interaction: { mode: 'index', intersect: false },
            plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, padding: 12 } } },
            elements: { line: { tension: 0.35, borderWidth: 2 }, point: { radius: 0, hoverRadius: 4 } },
            scales: {
                x: { ticks: { maxRotation: 35, minRotation: 0, autoSkip: false }, grid: { color: 'rgba(128,128,128,0.12)' } },
                y: { beginAtZero: true, grid: { color: 'rgba(128,128,128,0.16)' } }
            }
        }
    });
}

function renderLiveAlertsPage() {
    const tbody = document.getElementById('alerts-table-body');
    const total = liveAlertsCache.length;
    const totalPages = Math.max(1, Math.ceil(total / livePageSize));
    if (liveCurrentPage > totalPages) liveCurrentPage = totalPages;
    if (liveCurrentPage < 1) liveCurrentPage = 1;

    const startIndex = (liveCurrentPage - 1) * livePageSize;
    const endIndex = Math.min(startIndex + livePageSize, total);
    const pageAlerts = liveAlertsCache.slice(startIndex, endIndex);

    document.getElementById('kpi-live-count').textContent = window.liveTotalCount ?? total;
    document.getElementById('kpi-live-ips').textContent = new Set(liveAlertsCache.map(a => a.src_ip)).size;
    document.getElementById('kpi-live-last').textContent = total ? liveAlertsCache[0].display_time : '--:--:--';

    document.getElementById('live-pagination-info').textContent = `Page ${liveCurrentPage} / ${totalPages}`;
    document.getElementById('live-range-info').textContent = total
        ? `${startIndex + 1}-${endIndex} sur ${total} alertes chargées`
        : '0 alerte affichée';
    document.getElementById('live-prev-btn').disabled = liveCurrentPage <= 1;
    document.getElementById('live-next-btn').disabled = liveCurrentPage >= totalPages;

    tbody.innerHTML = pageAlerts.length ? pageAlerts.map(a => `<tr><td>${esc(a.display_time)}</td><td><span class="badge ${badgeClass(a.alert_type)}">${esc(a.alert_type)}</span></td><td><span class="clickable-ip" onclick="openIp('${esc(a.src_ip)}')">${esc(a.src_ip)}</span></td><td>${esc(a.dest_ip)}</td><td>${esc(a.protocol)}</td><td>${esc(a.path)}</td><td>${a.count_value !== null && a.count_value !== undefined ? esc(a.count_value) : '-'}</td></tr>`).join('') : '<tr><td colspan="7" class="empty">Aucune alerte live.</td></tr>';
}

function setLivePageSize() {
    livePageSize = Number(document.getElementById('live-page-size-select')?.value || 100);
    liveCurrentPage = 1;
    renderLiveAlertsPage();
}

function changeLivePage(delta) {
    liveCurrentPage += delta;
    renderLiveAlertsPage();
}

async function fetchLiveAlerts() {
    try {
        const res = await fetch(`/api/alerts?limit=${LIVE_FETCH_LIMIT}`);
        const payload = await res.json();
        liveAlertsCache = payload.alerts || [];
        window.liveTotalCount = payload.total_count ?? payload.count ?? liveAlertsCache.length;
        renderLiveAlertsPage();
        document.getElementById('last-refresh-live').textContent = 'MAJ: ' + new Date().toLocaleTimeString('fr-FR');
    } catch(e) { console.error(e); }
}
function dominantTargetType(r) {
    const types = [
        {name: 'SQLi', value: num(r.sqli_count)},
        {name: 'Scan', value: num(r.scan_count)},
        {name: 'XSS', value: num(r.xss_count)},
        {name: 'Exfiltration', value: num(r.exfiltration_count)},
        {name: 'Accès fichiers', value: num(r.file_attack_count)},
        {name: 'Admin probing', value: num(r.admin_probe_count)},
        {name: 'Fichiers sensibles', value: num(r.sensitive_file_count)},
        {name: 'Command injection', value: num(r.command_injection_count)}
    ].filter(x => x.value > 0);

    if (!types.length) return '-';
    types.sort((a, b) => b.value - a.value);
    return `${types[0].name} (${types[0].value})`;
}

function targetCategoriesText(r) {
    const types = [
        {name: 'SQLi', value: num(r.sqli_count)},
        {name: 'Scan', value: num(r.scan_count)},
        {name: 'XSS', value: num(r.xss_count)},
        {name: 'Exfiltration', value: num(r.exfiltration_count)},
        {name: 'Accès fichiers', value: num(r.file_attack_count)},
        {name: 'Admin probing', value: num(r.admin_probe_count)},
        {name: 'Fichiers sensibles', value: num(r.sensitive_file_count)},
        {name: 'Command injection', value: num(r.command_injection_count)}
    ].filter(x => x.value > 0);

    if (!types.length) return '-';
    return types.map(x => `${x.name}=${x.value}`).join(' | ');
}

async function fetchAnalytics() {
    try {
        const res = await fetch('/api/batch/analytics');
        const data = await res.json();
        const ipRep = data.ip_reputation || [], highRisk = data.high_risk_ips || [], targets = data.target_ip_stats || [], patterns = data.global_attack_patterns || [], timeline = data.threat_timeline || [], protocols = data.global_protocol_stats || [], relations = data.attacker_victim_stats || [];
        // KPI = vrais compteurs HBase envoyés par app.py.
        // Les tableaux/graphiques utilisent les listes limitées : Top 100 / Top 80 / Top 50.
        document.getElementById('kpi-ip-reputation').textContent =
            data.ip_reputation_total ?? ipRep.length;

        document.getElementById('kpi-high-risk').textContent =
            data.high_risk_ips_total ?? highRisk.length;

        document.getElementById('kpi-targets').textContent =
            data.target_ip_stats_total ?? targets.length;

        document.getElementById('kpi-patterns').textContent =
            data.global_attack_patterns_total ?? patterns.length;

        document.getElementById('kpi-timeline').textContent =
            data.threat_timeline_total ?? timeline.length;

        makeDoughnut('riskDistributionChart', (data.risk_distribution || []).map(x => x.name), (data.risk_distribution || []).map(x => x.value));
        makeBar('highRiskChart', highRisk.slice(0, 10).map(x => x.key), highRisk.slice(0, 10).map(x => num(x.risk_score)));
        makeBar('targetChart', targets.slice(0, 10).map(x => x.key), targets.slice(0, 10).map(x => num(x.alert_count)));
        makeBar('patternsChart', patterns.slice(0, 12).map(x => x.key), patterns.slice(0, 12).map(x => num(x.alert_count)));
        makeDoughnut('protocolChart', protocols.slice(0, 8).map(x => x.key), protocols.slice(0, 8).map(x => num(x.alert_count)));
        const lastTimeline = timeline.slice(-24);
        makeLine('timelineChart', lastTimeline.map(x => x.key), [
            { label:'Total', data:lastTimeline.map(x=>num(x.total_alerts)), borderColor:'#00b7ff', backgroundColor:'rgba(0,183,255,0.10)', fill:true, borderWidth:3 },
            { label:'SQLi', data:lastTimeline.map(x=>num(x.sqli_count)), borderColor:'#ff5d73', backgroundColor:'rgba(255,93,115,0.06)', fill:false },
            { label:'Scan', data:lastTimeline.map(x=>num(x.scan_count)), borderColor:'#ffb020', backgroundColor:'rgba(255,176,32,0.06)', fill:false },
            { label:'XSS', data:lastTimeline.map(x=>num(x.xss_count)), borderColor:'#a78bfa', backgroundColor:'rgba(167,139,250,0.06)', fill:false },
            { label:'Bruteforce', data:lastTimeline.map(x=>num(x.bruteforce_count)), borderColor:'#f97316', backgroundColor:'rgba(249,115,22,0.06)', fill:false },
            { label:'Exfiltration', data:lastTimeline.map(x=>num(x.exfiltration_count)), borderColor:'#38bdf8', backgroundColor:'rgba(56,189,248,0.06)', fill:false },
            { label:'File access', data:lastTimeline.map(x=>num(x.file_attack_count)), borderColor:'#22c55e', backgroundColor:'rgba(34,197,94,0.06)', fill:false },
            { label:'Admin probing', data:lastTimeline.map(x=>num(x.admin_probe_count)), borderColor:'#eab308', backgroundColor:'rgba(234,179,8,0.06)', fill:false },
            { label:'Sensitive file', data:lastTimeline.map(x=>num(x.sensitive_file_count)), borderColor:'#ec4899', backgroundColor:'rgba(236,72,153,0.06)', fill:false },
            { label:'Command injection', data:lastTimeline.map(x=>num(x.command_injection_count)), borderColor:'#ef4444', backgroundColor:'rgba(239,68,68,0.06)', fill:false }
        ]);
        const ipBody = document.getElementById('ip-reputation-body');
        ipBody.innerHTML = ipRep.length ? ipRep.slice(0,50).map(r => `<tr><td><span class="clickable-ip" onclick="openIp('${esc(r.key)}')">${esc(r.key)}</span></td><td><b>${esc(r.risk_score || 0)}</b></td><td>${riskBadge(r.risk_level)}</td><td>${esc(r.total_alerts || 0)}</td><td>${esc(r.malicious_count || 0)}</td><td>${esc(r.suspicious_count || 0)}</td><td>${esc(r.sqli_count || 0)}</td><td>${esc(r.xss_count || 0)}</td><td>${esc(r.scan_count || 0)}</td><td>${esc(r.bruteforce_count || 0)}</td><td>${esc(r.exfiltration_count || 0)}</td><td>${esc(r.unique_targets || 0)}</td><td>${esc(formatDateTime(r.last_live || '-'))}</td></tr>`).join('') : '<tr><td colspan="13" class="empty">Aucune donnée ip_reputation. Lance le batch enrichi.</td></tr>';
        document.getElementById('relations-body').innerHTML = relations.slice(0,30).map(r => `<tr><td><span class="clickable-ip" onclick="openIp('${esc(r.src_ip || '')}')">${esc(r.src_ip)}</span></td><td>${esc(r.dest_ip)}</td><td><b>${esc(r.relation_risk_score || 0)}</b></td><td>${esc(r.alert_count || 0)}</td><td>${esc(r.sqli_count || 0)}</td><td>${esc(r.scan_count || 0)}</td><td>${esc(r.total_bytes || 0)}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">Aucune donnée relation.</td></tr>';
        document.getElementById('targets-body').innerHTML = targets.slice(0,30).map(r => `
<tr>
    <td>${esc(r.key || r.dest_ip || '-')}</td>
    <td><b>${esc(r.target_risk_score || 0)} / 100</b></td>
    <td>${esc(r.alert_count || 0)}</td>
    <td>${esc(r.unique_attackers || 0)}</td>
    <td><span class="badge ${badgeClass(dominantTargetType(r))}">${esc(dominantTargetType(r))}</span></td>
    <td>${esc(targetCategoriesText(r))}</td>
    <td>${esc(r.last_archived_at || r.last_seen || '-')}</td>
</tr>
`).join('') || '<tr><td colspan="7" class="empty">Aucune machine ciblée trouvée. Relance le batch après l’archivage HDFS.</td></tr>';
        document.getElementById('last-refresh-batch').textContent = 'MAJ: ' + new Date().toLocaleTimeString('fr-FR');
    } catch(e) { console.error(e); }
}

async function fetchIpDetail(ip) {
    const container = document.getElementById('ip-detail-container');
    container.innerHTML = '<div class="empty">Chargement de la fiche IP...</div>';

    try {
        const res = await fetch(`/api/threat/ip/${encodeURIComponent(ip)}`);
        const data = await res.json();
        if (data.error) {
            container.innerHTML = `<div class="empty">Erreur : ${esc(data.error)}</div>`;
            return;
        }

        const h = data.historical || {};
        const live = data.live || {};
        const combined = data.combined || {};
        const rec = data.recommendation || {};
        const relations = data.relations || [];
        const alerts = live.alerts || [];
        const histAlerts = data.historical_alerts || [];
        const score = num(h.risk_score);
        const deg = Math.min(100, score) * 3.6;

        const signalRows = [
    { label:'Logs malveillants', batch:num(h.malicious_count), live:0, note:'Classification threat_label=malicious' },
    { label:'Logs suspects', batch:num(h.suspicious_count), live:0, note:'Classification threat_label=suspicious' },
    { label:'SQLi / SQLMap', batch:num(h.sqli_count), live:num(live.sqli_live), note:'Injection SQL ou outil SQLMap' },
    { label:'Scans', batch:num(h.scan_count), live:num(live.scan_live), note:'Nmap, Nikto, Masscan ou signatures de scan' },
    { label:'XSS', batch:num(h.xss_count), live:num(live.xss_live), note:'Tentatives Cross-Site Scripting' },
    { label:'Bruteforce', batch:num(h.bruteforce_count), live:num(live.bruteforce_live), note:'Activité bloquée répétée ou tentatives login' },
    { label:'Exfiltration', batch:num(h.exfiltration_count), live:num(live.exfiltration_live), note:'Volume anormal ou transfert suspect' },
    { label:'Accès fichiers', batch:num(h.file_attack_count), live:0, note:'Tentatives d’accès à des fichiers sensibles' },
    { label:'Admin probing', batch:num(h.admin_probe_count), live:0, note:'Accès aux chemins administrateur' },
    { label:'Fichiers sensibles', batch:num(h.sensitive_file_count), live:0, note:'Exposition .env, .git, backup, etc.' },
    { label:'Command injection', batch:num(h.command_injection_count), live:0, note:'Tentatives cmd, exec, powershell, curl, wget' }
].map(x => ({ ...x, total: x.batch + x.live }));

const activeSignalRows = signalRows.filter(x => x.total >= 1);

const activeSignalTableHtml = activeSignalRows.length
    ? activeSignalRows.map(x => `
        <tr>
            <td>${esc(x.label)}</td>
            <td>${esc(x.batch)}</td>
            <td>${esc(x.live)}</td>
            <td>${esc(x.total)}</td>
            <td>${esc(x.note)}</td>
        </tr>
    `).join('')
    : '<tr><td colspan="5" class="empty">Aucune catégorie positive détectée pour cette IP.</td></tr>';

const allSignalsHtml = signalRows.map(x => `
    <div class="metric">
        <div class="label">${esc(x.label)}</div>
        <div class="value">${esc(x.total)}</div>
        <div class="kpi-sub">Batch: ${esc(x.batch)} | Live: ${esc(x.live)}</div>
    </div>
`).join('');

        const histAlertsHtml = histAlerts.length
            ? `<div class="table-wrapper"><table><thead><tr><th>Archivé le</th><th>Heure log</th><th>IP destination</th><th>Protocole</th><th>Chemin</th><th>Alerte</th><th>Catégorie</th></tr></thead><tbody>${histAlerts.map(a => `<tr><td>${esc(formatDateTime(a.archived_at || '-'))}</td><td>${esc(formatDateTime(a.event_time || '-'))}</td><td>${esc(a.dest_ip || '-')}</td><td>${esc(a.protocol || '-')}</td><td>${esc(a.path || '-')}</td><td><span class="badge ${badgeClass(a.alert_type)}">${esc(a.alert_type || '-')}</span></td><td>${esc(a.attack_category || a.category || '-')}</td></tr>`).join('')}</tbody></table></div>`
            : `<div class="empty">Aucune alerte historique détaillée trouvée pour cette IP. Vérifie que le batch final remplit bien la table <b>ip_historical_alerts</b>.</div>`;

        const relationsPanel = relations.length ? `
            <div class="panel span-12">
                <h3 class="section-title">Machines ciblées par cette IP</h3>
                <p class="section-sub">Résumé agrégé par destination. Une ligne = une machine ciblée par cette IP. Le niveau relation est calculé à partir du nombre d’alertes et de leur gravité.</p>
                <div class="table-wrapper"><table><thead><tr><th>Machine ciblée</th><th>Niveau relation</th><th>Alertes</th><th>Types détectés</th><th>Volume</th><th>Dernière activité</th></tr></thead><tbody>
                    ${relations.map(r => {
                        const level = relationLevel(r.relation_risk_score);
                        return `<tr><td>${esc(r.dest_ip)}</td><td><b>${esc(level)}</b><br><span class="pill">${esc(r.relation_risk_score || 0)} / 100</span></td><td>${esc(r.alert_count || 0)}</td><td>${esc(relationTypesText(r))}</td><td>${esc(r.total_bytes || 0)} bytes</td><td>${esc(formatDateTime(r.last_archived_at || r.last_seen || '-'))}</td></tr>`;
                    }).join('')}
                </tbody></table></div>
            </div>` : '';

        container.innerHTML = `
        <div class="detail-layout">
            <div class="ip-hero">
                <p class="ip-address">${esc(data.ip)}</p>
                <div class="split-title"><span class="pill">Score batch HBase</span>${riskBadge(h.risk_level || rec.level)}</div>
                <div class="score-circle" style="--score-deg:${deg}deg;"><span>${score}</span></div>
                <div class="metric-grid">
                    <div class="metric"><div class="label">Alertes batch</div><div class="value">${esc(h.total_alerts || 0)}</div></div>
                    <div class="metric"><div class="label">Alertes live</div><div class="value">${esc(live.active_alerts || 0)}</div></div>
                    <div class="metric"><div class="label">Total affiché</div><div class="value">${esc(combined.total_alerts_visible || 0)}</div></div>
                    <div class="metric"><div class="label">Dernière live</div><div class="value" style="font-size:15px;">${esc(formatDateTime(live.last_seen || '-'))}</div></div>
                </div>
                <div style="margin-top:16px;padding:14px;border-radius:16px;background:var(--panel-soft);border:1px solid var(--border);"><div class="kpi-label">Recommandation actuelle</div><div style="font-size:20px;font-weight:1000;margin-top:8px;color:var(--strong);">${esc(rec.action || '-')}</div><div class="kpi-sub">${esc(rec.reason || '-')}</div></div>
            </div>

            <div class="dashboard-grid">
                <div class="panel span-12">
    <h3 class="section-title">Synthèse des signaux détectés</h3>
    <div class="table-wrapper summary-table-wrapper">
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Catégorie</th>
                    <th>Batch</th>
                    <th>Live</th>
                    <th>Total affiché</th>
                    <th>Interprétation</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Alertes totales</td>
                    <td>${esc(h.total_alerts || 0)}</td>
                    <td>${esc(live.active_alerts || 0)}</td>
                    <td>${esc(combined.total_alerts_visible || 0)}</td>
                    <td>Volume global d’alertes observées pour cette IP.</td>
                </tr>
                <tr>
                    <td>Cibles uniques</td>
                    <td>${esc(h.unique_targets || 0)}</td>
                    <td>${esc(live.unique_targets_live || 0)}</td>
                    <td>-</td>
                    <td>Nombre de machines menacées</td>
                </tr>
                <tr>
                    <td>Protocoles uniques</td>
                    <td>${esc(h.unique_protocols || 0)}</td>
                    <td>${esc(live.unique_protocols_live || 0)}</td>
                    <td>-</td>
                    <td>Protocoles observés dans les événements de cette IP.</td>
                </tr>
                ${activeSignalTableHtml}
            </tbody>
        </table>
    </div>
</div>

                <div class="panel span-12">
                    <h3 class="section-title">Attaques archivées de cette IP</h3>
                    <p class="section-sub">Historique des alertes stockées pour cet IP</p>
                    ${histAlertsHtml}
                </div>

               <div class="panel span-12">
    <h3 class="section-title">Résumé général des catégories</h3>
    <p class="section-sub">
        Vue complète de toutes les catégories pour cette IP, y compris celles dont la valeur est égale à 0.
    </p>

    <div class="metric-grid" style="grid-template-columns: repeat(4, 1fr); margin-top:14px;">
        ${allSignalsHtml}
    </div>

    <div class="metric" style="margin-top:12px;">
        <div class="label">Volume total historique</div>
        <div class="value" style="font-size:18px;">${esc(h.total_bytes || 0)} bytes</div>
    </div>
</div>

                ${relationsPanel}

                <div class="panel span-12">
                    <h3 class="section-title">Alertes live récentes de cette IP</h3>
                    <p class="section-sub">Ces lignes viennent uniquement de Cassandra. Elles expliquent les compteurs live.</p>
                    <div class="table-wrapper"><table><thead><tr><th>Heure</th><th>Alerte</th><th>Destination live</th><th>Protocole live</th><th>Chemin</th><th>Détail</th></tr></thead><tbody>
                        ${alerts.length ? alerts.map(a => `<tr><td>${esc(a.display_time)}</td><td><span class="badge ${badgeClass(a.alert_type)}">${esc(a.alert_type)}</span></td><td>${esc(a.dest_ip)}</td><td>${esc(a.protocol)}</td><td>${esc(a.path)}</td><td>${a.count_value !== null && a.count_value !== undefined ? esc(a.count_value) : '-'}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">Aucune alerte live récente.</td></tr>'}
                    </tbody></table></div>
                </div>
            </div>
        </div>`;
    } catch(e) {
        console.error(e);
        container.innerHTML = '<div class="empty">Erreur pendant le chargement de la fiche IP.</div>';
    }
}
fetchLiveAlerts(); fetchAnalytics(); setInterval(fetchLiveAlerts, 2000); setInterval(fetchAnalytics, 10000);

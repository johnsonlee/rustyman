// State
let trafficEntries = new Map();
let eventSource = null;
let currentRuleType = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initEventStream();
    loadInitialData();
    initEventListeners();
});

// Tab navigation
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tc => tc.classList.remove('active'));

            const tabId = tab.dataset.tab + '-tab';
            document.getElementById(tabId).classList.add('active');

            if (tab.dataset.tab === 'rules') {
                loadRules();
            } else if (tab.dataset.tab === 'settings') {
                loadStats();
            }
        });
    });
}

// Server-Sent Events for real-time updates
function initEventStream() {
    // Close existing connection if any
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource('/api/events');

    // Listen for specific event types
    eventSource.addEventListener('request', (event) => {
        const data = JSON.parse(event.data);
        handleTrafficEvent({ event_type: 'new_request', data: data.data });
    });

    eventSource.addEventListener('response', (event) => {
        const data = JSON.parse(event.data);
        handleTrafficEvent({ event_type: 'response_received', data: data.data });
    });

    eventSource.addEventListener('completed', (event) => {
        const data = JSON.parse(event.data);
        handleTrafficEvent({ event_type: 'completed', data: data.data });
    });

    eventSource.addEventListener('cleared', (event) => {
        handleTrafficEvent({ event_type: 'cleared', data: null });
    });

    eventSource.onerror = (error) => {
        console.error('EventSource error:', error);
        // Reconnect after 3 seconds
        setTimeout(() => {
            if (eventSource.readyState === EventSource.CLOSED) {
                initEventStream();
            }
        }, 3000);
    };
}

// Handle traffic events
function handleTrafficEvent(event) {
    const { event_type, data } = event;

    switch (event_type) {
        case 'new_request':
        case 'response_received':
        case 'completed':
            trafficEntries.set(data.id, data);
            updateTrafficRow(data);
            updateTrafficCount();
            break;
        case 'cleared':
            trafficEntries.clear();
            document.getElementById('traffic-body').innerHTML = '';
            updateTrafficCount();
            break;
    }
}

// Update or insert traffic row
function updateTrafficRow(entry) {
    const tbody = document.getElementById('traffic-body');
    let row = document.getElementById(`row-${entry.id}`);

    if (!row) {
        row = document.createElement('tr');
        row.id = `row-${entry.id}`;
        row.onclick = () => showTrafficDetail(entry.id);
        tbody.insertBefore(row, tbody.firstChild);
    }

    const status = entry.response ? entry.response.status : '-';
    const statusClass = getStatusClass(status);
    const methodClass = `method-${entry.request.method.toLowerCase()}`;

    const contentType = entry.response?.headers['content-type'] || '-';
    const shortType = contentType.split(';')[0].split('/').pop();

    const size = entry.response ? formatSize(entry.response.body_size) : '-';
    const time = entry.timing.completed
        ? `${new Date(entry.timing.completed) - new Date(entry.timing.request_received)}ms`
        : '-';

    const modified = entry.response?.modified
        ? '<span class="tag tag-modified">modified</span>'
        : '';

    row.innerHTML = `
        <td><span class="status ${statusClass}">${status}</span></td>
        <td class="${methodClass}">${entry.request.method}</td>
        <td>${entry.request.host}</td>
        <td>${entry.request.path}${modified}</td>
        <td>${shortType}</td>
        <td>${size}</td>
        <td>${time}</td>
    `;
}

// Get status class
function getStatusClass(status) {
    if (status === '-') return 'status-pending';
    if (status >= 200 && status < 300) return 'status-2xx';
    if (status >= 300 && status < 400) return 'status-3xx';
    if (status >= 400 && status < 500) return 'status-4xx';
    return 'status-5xx';
}

// Format size
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Update traffic count
function updateTrafficCount() {
    document.getElementById('traffic-count').textContent = trafficEntries.size;
}

// Load initial data
async function loadInitialData() {
    try {
        const response = await fetch('/api/traffic?limit=100');
        const data = await response.json();
        if (data.success && data.data) {
            data.data.forEach(entry => {
                trafficEntries.set(entry.id, entry);
                updateTrafficRow(entry);
            });
            updateTrafficCount();
        }
    } catch (error) {
        console.error('Failed to load traffic:', error);
    }
}

// Event listeners
function initEventListeners() {
    // Clear traffic
    document.getElementById('clear-btn').addEventListener('click', async () => {
        if (confirm('Clear all traffic?')) {
            await fetch('/api/traffic/clear', { method: 'POST' });
        }
    });

    // Search
    let searchTimeout;
    document.getElementById('search-input').addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => searchTraffic(e.target.value), 300);
    });
}

// Search traffic
async function searchTraffic(query) {
    if (!query) {
        // Reload all traffic
        document.getElementById('traffic-body').innerHTML = '';
        trafficEntries.forEach(entry => updateTrafficRow(entry));
        return;
    }

    try {
        const response = await fetch(`/api/traffic/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        if (data.success && data.data) {
            document.getElementById('traffic-body').innerHTML = '';
            data.data.forEach(entry => updateTrafficRow(entry));
        }
    } catch (error) {
        console.error('Search failed:', error);
    }
}

// Show traffic detail
function showTrafficDetail(id) {
    const entry = trafficEntries.get(id);
    if (!entry) return;

    const content = document.getElementById('detail-content');

    // Format headers
    const formatHeaders = (headers) => {
        return Object.entries(headers || {})
            .map(([k, v]) => `<div class="detail-row"><span class="detail-key">${k}:</span><span class="detail-value">${escapeHtml(v)}</span></div>`)
            .join('');
    };

    // Format body
    const formatBody = (body) => {
        if (!body) return '<em>No body</em>';
        try {
            // Try to decode as text
            const text = typeof body === 'string' ? body : new TextDecoder().decode(new Uint8Array(body));
            // Try to parse as JSON for pretty printing
            try {
                const json = JSON.parse(text);
                return escapeHtml(JSON.stringify(json, null, 2));
            } catch {
                return escapeHtml(text.substring(0, 10000));
            }
        } catch {
            return '<em>Binary data</em>';
        }
    };

    content.innerHTML = `
        <div class="detail-section">
            <h3>Request</h3>
            <div class="detail-row">
                <span class="detail-key">URL:</span>
                <span class="detail-value">${escapeHtml(entry.request.url)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">Method:</span>
                <span class="detail-value">${entry.request.method}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">Client:</span>
                <span class="detail-value">${entry.request.client_addr}</span>
            </div>
            <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Headers</h4>
            ${formatHeaders(entry.request.headers)}
            ${entry.request.body ? `
                <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Body</h4>
                <div class="detail-body">${formatBody(entry.request.body)}</div>
            ` : ''}
        </div>

        ${entry.response ? `
            <div class="detail-section">
                <h3>Response</h3>
                <div class="detail-row">
                    <span class="detail-key">Status:</span>
                    <span class="detail-value">${entry.response.status} ${entry.response.reason}</span>
                </div>
                ${entry.response.modified ? `
                    <div class="detail-row">
                        <span class="detail-key">Modified:</span>
                        <span class="detail-value">${entry.response.modification_source || 'Yes'}</span>
                    </div>
                ` : ''}
                <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Headers</h4>
                ${formatHeaders(entry.response.headers)}
                ${entry.response.body ? `
                    <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Body</h4>
                    <div class="detail-body">${formatBody(entry.response.body)}</div>
                ` : ''}
            </div>
        ` : '<div class="detail-section"><h3>Response</h3><em>Pending...</em></div>'}

        ${entry.matched_rules.length > 0 ? `
            <div class="detail-section">
                <h3>Matched Rules</h3>
                ${entry.matched_rules.map(r => `
                    <div class="detail-row">
                        <span class="detail-key">${r.rule_type}:</span>
                        <span class="detail-value">${r.rule_name}</span>
                    </div>
                `).join('')}
            </div>
        ` : ''}

        <div class="detail-section">
            <h3>Timing</h3>
            <div class="detail-row">
                <span class="detail-key">Request:</span>
                <span class="detail-value">${new Date(entry.timing.request_received).toLocaleString()}</span>
            </div>
            ${entry.timing.completed ? `
                <div class="detail-row">
                    <span class="detail-key">Duration:</span>
                    <span class="detail-value">${new Date(entry.timing.completed) - new Date(entry.timing.request_received)}ms</span>
                </div>
            ` : ''}
        </div>
    `;

    document.getElementById('detail-modal').classList.add('active');
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal
function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// Load rules
async function loadRules() {
    try {
        const [mapRemote, mapLocal, header] = await Promise.all([
            fetch('/api/rules/map-remote').then(r => r.json()),
            fetch('/api/rules/map-local').then(r => r.json()),
            fetch('/api/rules/header').then(r => r.json())
        ]);

        renderRules('map-remote-rules', mapRemote.data || [], 'map-remote');
        renderRules('map-local-rules', mapLocal.data || [], 'map-local');
        renderRules('header-rules', header.data || [], 'header');
    } catch (error) {
        console.error('Failed to load rules:', error);
    }
}

// Render rules
function renderRules(containerId, rules, type) {
    const container = document.getElementById(containerId);
    if (rules.length === 0) {
        container.innerHTML = '<div class="rule-item"><em>No rules configured</em></div>';
        return;
    }

    container.innerHTML = rules.map(rule => `
        <div class="rule-item ${rule.enabled ? '' : 'disabled'}">
            <div>
                <span class="rule-name">${escapeHtml(rule.name)}</span>
                <div class="rule-pattern">${escapeHtml(rule.pattern || rule.url_pattern)}</div>
            </div>
            <div>
                ${type === 'map-remote' ? `→ ${escapeHtml(rule.target)}` : ''}
                ${type === 'map-local' ? `→ ${escapeHtml(rule.local_path)}` : ''}
            </div>
        </div>
    `).join('');
}

// Show add rule modal
function showAddRuleModal(type) {
    currentRuleType = type;
    const title = {
        'map-remote': 'Add Map Remote Rule',
        'map-local': 'Add Map Local Rule',
        'header': 'Add Header Rule'
    }[type];

    document.getElementById('add-rule-title').textContent = title;

    const formContent = document.getElementById('rule-form-content');

    if (type === 'map-remote') {
        formContent.innerHTML = `
            <div class="form-group">
                <label>Rule Name</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>URL Pattern (regex)</label>
                <input type="text" name="pattern" placeholder="https://api\\.example\\.com/.*" required>
            </div>
            <div class="form-group">
                <label>Target URL</label>
                <input type="text" name="target" placeholder="https://staging.example.com" required>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="preserve_path" checked> Preserve Path</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="preserve_query" checked> Preserve Query</label>
            </div>
        `;
    } else if (type === 'map-local') {
        formContent.innerHTML = `
            <div class="form-group">
                <label>Rule Name</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>URL Pattern (regex)</label>
                <input type="text" name="pattern" placeholder="https://example\\.com/api/.*" required>
            </div>
            <div class="form-group">
                <label>Local Path</label>
                <input type="text" name="local_path" placeholder="/path/to/local/file.json" required>
            </div>
            <div class="form-group">
                <label>MIME Type (optional)</label>
                <input type="text" name="mime_type" placeholder="application/json">
            </div>
        `;
    } else if (type === 'header') {
        formContent.innerHTML = `
            <div class="form-group">
                <label>Rule Name</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>URL Pattern (regex)</label>
                <input type="text" name="url_pattern" placeholder=".*" required>
            </div>
            <div class="form-group">
                <label>Action</label>
                <select name="action">
                    <option value="add">Add Header</option>
                    <option value="remove">Remove Header</option>
                    <option value="modify">Modify Header</option>
                </select>
            </div>
            <div class="form-group">
                <label>Header Name</label>
                <input type="text" name="header_name" placeholder="X-Custom-Header" required>
            </div>
            <div class="form-group">
                <label>Header Value</label>
                <input type="text" name="header_value" placeholder="value">
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="apply_to_request" checked> Apply to Request</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="apply_to_response" checked> Apply to Response</label>
            </div>
        `;
    }

    document.getElementById('add-rule-modal').classList.add('active');
}

// Submit rule
async function submitRule(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);

    let endpoint, body;

    if (currentRuleType === 'map-remote') {
        endpoint = '/api/rules/map-remote';
        body = {
            name: formData.get('name'),
            enabled: true,
            pattern: formData.get('pattern'),
            target: formData.get('target'),
            preserve_path: formData.get('preserve_path') === 'on',
            preserve_query: formData.get('preserve_query') === 'on'
        };
    } else if (currentRuleType === 'map-local') {
        endpoint = '/api/rules/map-local';
        body = {
            name: formData.get('name'),
            enabled: true,
            pattern: formData.get('pattern'),
            local_path: formData.get('local_path'),
            mime_type: formData.get('mime_type') || null
        };
    } else if (currentRuleType === 'header') {
        endpoint = '/api/rules/header';
        body = {
            name: formData.get('name'),
            enabled: true,
            url_pattern: formData.get('url_pattern'),
            apply_to_request: formData.get('apply_to_request') === 'on',
            apply_to_response: formData.get('apply_to_response') === 'on',
            operations: [{
                action: formData.get('action'),
                name: formData.get('header_name'),
                value: formData.get('header_value') || null,
                value_pattern: null,
                replacement: null
            }]
        };
    }

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        if (data.success) {
            closeModal('add-rule-modal');
            loadRules();
        } else {
            alert('Failed to add rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Failed to add rule: ' + error.message);
    }
}

// Load stats
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        if (data.success && data.data) {
            document.getElementById('stat-traffic').textContent = data.data.traffic_count;
            document.getElementById('stat-certs').textContent = data.data.cert_cache_size;
            document.getElementById('stat-map-remote').textContent = data.data.map_remote_rules;
            document.getElementById('stat-map-local').textContent = data.data.map_local_rules;
            document.getElementById('stat-header').textContent = data.data.header_rules;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Click outside modal to close
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('active');
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }
});

// State
let trafficEntries = new Map();
let eventSource = null;
let currentRuleType = null;
let currentView = 'list';
let currentFilter = '';
let expandedNodes = new Set(); // Track expanded tree nodes

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initViewTabs();
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

// View tabs (List/Tree)
function initViewTabs() {
    const viewTabs = document.querySelectorAll('.view-tab');
    viewTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            viewTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            currentView = tab.dataset.view;

            const viewContainers = document.querySelectorAll('.view-container');
            viewContainers.forEach(vc => vc.classList.remove('active'));

            document.getElementById(`${currentView}-view`).classList.add('active');

            if (currentView === 'tree') {
                renderTreeView();
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
            if (currentView === 'tree') {
                renderTreeView();
            }
            applyFilter();
            updateTrafficCount();
            break;
        case 'cleared':
            trafficEntries.clear();
            document.getElementById('traffic-body').innerHTML = '';
            document.getElementById('traffic-tree').innerHTML = '';
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
        const response = await fetch('/api/traffic?limit=500');
        const data = await response.json();
        if (data.success && data.data) {
            data.data.forEach(entry => {
                trafficEntries.set(entry.id, entry);
                updateTrafficRow(entry);
            });
            renderTreeView();
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

    // Real-time filter
    document.getElementById('search-input').addEventListener('input', (e) => {
        currentFilter = e.target.value.toLowerCase();
        applyFilter();
    });
}

// Apply filter to current view
function applyFilter() {
    if (currentView === 'list') {
        applyListFilter();
    } else {
        applyTreeFilter();
    }
    updateFilteredCount();
}

// Apply filter to list view
function applyListFilter() {
    const rows = document.querySelectorAll('#traffic-body tr');
    rows.forEach(row => {
        const id = row.id.replace('row-', '');
        const entry = trafficEntries.get(id);
        if (entry && matchesFilter(entry)) {
            row.classList.remove('hidden');
        } else {
            row.classList.add('hidden');
        }
    });
}

// Apply filter to tree view
function applyTreeFilter() {
    const hosts = document.querySelectorAll('.tree-host');
    hosts.forEach(hostEl => {
        const items = hostEl.querySelectorAll('.tree-item');
        let visibleCount = 0;

        items.forEach(item => {
            const id = item.dataset.id;
            const entry = trafficEntries.get(id);
            if (entry && matchesFilter(entry)) {
                item.classList.remove('hidden');
                visibleCount++;
            } else {
                item.classList.add('hidden');
            }
        });

        // Update node counts based on visible items
        const nodes = hostEl.querySelectorAll('.tree-node');
        nodes.forEach(node => {
            const nodeItems = node.querySelectorAll(':scope > .tree-node-children > .tree-item:not(.hidden)');
            const childNodes = node.querySelectorAll(':scope > .tree-node-children > .tree-node:not(.hidden)');
            const nodeCount = node.querySelector('.tree-node-count');

            // Count visible items in this node and descendants
            const allItems = node.querySelectorAll('.tree-item:not(.hidden)');
            if (nodeCount) {
                nodeCount.textContent = allItems.length;
            }

            if (allItems.length > 0) {
                node.classList.remove('hidden');
            } else {
                node.classList.add('hidden');
            }
        });

        if (visibleCount > 0) {
            hostEl.classList.remove('hidden');
            hostEl.querySelector('.tree-host-count').textContent = `${visibleCount} requests`;
        } else {
            hostEl.classList.add('hidden');
        }
    });
}

// Check if entry matches filter
function matchesFilter(entry) {
    if (!currentFilter) return true;

    const searchText = [
        entry.request.url,
        entry.request.host,
        entry.request.path,
        entry.request.method,
        entry.response?.status?.toString() || ''
    ].join(' ').toLowerCase();

    // Support simple regex or plain text
    try {
        const regex = new RegExp(currentFilter, 'i');
        return regex.test(searchText);
    } catch {
        return searchText.includes(currentFilter);
    }
}

// Update filtered count
function updateFilteredCount() {
    if (!currentFilter) {
        document.getElementById('traffic-count').textContent = trafficEntries.size;
        return;
    }

    let count = 0;
    trafficEntries.forEach(entry => {
        if (matchesFilter(entry)) count++;
    });
    document.getElementById('traffic-count').textContent = `${count}/${trafficEntries.size}`;
}

// Build hierarchical path tree
function buildPathTree(entries) {
    const tree = {};

    entries.forEach(entry => {
        const path = entry.request.path || '/';
        // Split path into segments, filter empty ones
        const segments = path.split('/').filter(s => s);

        let current = tree;
        let currentPath = '';

        segments.forEach((segment, index) => {
            currentPath += '/' + segment;
            if (!current[segment]) {
                current[segment] = {
                    _path: currentPath,
                    _entries: [],
                    _children: {}
                };
            }
            // If last segment, add the entry
            if (index === segments.length - 1) {
                current[segment]._entries.push(entry);
            }
            current = current[segment]._children;
        });

        // Handle root path requests
        if (segments.length === 0) {
            if (!tree['']) {
                tree[''] = { _path: '/', _entries: [], _children: {} };
            }
            tree['']._entries.push(entry);
        }
    });

    return tree;
}

// Count all entries in a tree node (including children)
function countTreeEntries(node) {
    let count = node._entries ? node._entries.length : 0;
    if (node._children) {
        Object.values(node._children).forEach(child => {
            count += countTreeEntries(child);
        });
    }
    return count;
}

// Render a tree node recursively
function renderTreeNode(name, node, hostKey, depth = 0) {
    const nodeKey = `${hostKey}:${node._path || '/'}`;
    const isExpanded = expandedNodes.has(nodeKey);
    const entries = node._entries || [];
    const children = node._children || {};
    const childKeys = Object.keys(children).sort();
    const totalCount = countTreeEntries(node);
    const hasChildren = childKeys.length > 0 || entries.length > 0;

    if (!hasChildren) return '';

    const displayName = name || '/';
    const indent = depth * 16;

    // Render entries at this level
    const entryItems = entries.map(entry => {
        const status = entry.response ? entry.response.status : '-';
        const statusClass = getStatusClass(status);
        const time = entry.timing.completed
            ? `${new Date(entry.timing.completed) - new Date(entry.timing.request_received)}ms`
            : '-';
        const query = entry.request.path.includes('?')
            ? entry.request.path.substring(entry.request.path.indexOf('?'))
            : '';
        const size = entry.response ? formatSize(entry.response.body_size) : '-';
        const contentType = entry.response?.headers['content-type'] || '';
        const shortType = contentType.split(';')[0].split('/').pop() || '-';

        return `
            <div class="tree-item" data-id="${entry.id}" onclick="showTrafficDetail('${entry.id}')" style="padding-left: ${indent + 24}px;">
                <span class="status ${statusClass}">${status}</span>
                <span class="tree-query">${escapeHtml(query || '')}</span>
                <span class="tree-type">${shortType}</span>
                <span class="tree-size">${size}</span>
                <span class="time">${time}</span>
            </div>
        `;
    }).join('');

    // Render child nodes
    const childItems = childKeys.map(key =>
        renderTreeNode(key, children[key], hostKey, depth + 1)
    ).join('');

    // If this is a path segment node (not the implicit root)
    if (name !== null) {
        return `
            <div class="tree-node ${isExpanded ? 'expanded' : ''}" data-key="${escapeHtml(nodeKey)}">
                <div class="tree-node-header" onclick="toggleTreeNode('${escapeHtml(nodeKey)}')" style="padding-left: ${indent}px;">
                    <span class="expand-icon">▶</span>
                    <span class="tree-node-name">/${escapeHtml(displayName)}</span>
                    <span class="tree-node-count">${totalCount}</span>
                </div>
                <div class="tree-node-children">
                    ${entryItems}
                    ${childItems}
                </div>
            </div>
        `;
    }

    // Implicit root - just return children
    return entryItems + childItems;
}

// Render tree view
function renderTreeView() {
    const treeContainer = document.getElementById('traffic-tree');

    // Group by host
    const hostGroups = new Map();
    trafficEntries.forEach(entry => {
        const host = entry.request.host;
        if (!hostGroups.has(host)) {
            hostGroups.set(host, []);
        }
        hostGroups.get(host).push(entry);
    });

    // Sort hosts alphabetically
    const sortedHosts = Array.from(hostGroups.keys()).sort();

    treeContainer.innerHTML = sortedHosts.map(host => {
        const entries = hostGroups.get(host);
        const hostKey = `host:${host}`;
        const isExpanded = expandedNodes.has(hostKey);

        // Build path tree for this host
        const pathTree = buildPathTree(entries);

        // Render path tree
        const pathItems = Object.keys(pathTree).sort().map(key =>
            renderTreeNode(key, pathTree[key], host, 1)
        ).join('');

        return `
            <div class="tree-host ${isExpanded ? 'expanded' : ''}" data-host="${escapeHtml(host)}" data-key="${escapeHtml(hostKey)}">
                <div class="tree-host-header" onclick="toggleTreeNode('${escapeHtml(hostKey)}')">
                    <span class="expand-icon">▶</span>
                    <span class="tree-host-name">${escapeHtml(host)}</span>
                    <span class="tree-host-count">${entries.length} requests</span>
                </div>
                <div class="tree-items">
                    ${pathItems}
                </div>
            </div>
        `;
    }).join('');

    applyTreeFilter();
}

// Toggle tree node expand/collapse
function toggleTreeNode(nodeKey) {
    if (expandedNodes.has(nodeKey)) {
        expandedNodes.delete(nodeKey);
    } else {
        expandedNodes.add(nodeKey);
    }

    // Update DOM directly without full re-render
    const selector = `[data-key="${CSS.escape(nodeKey)}"]`;
    const el = document.querySelector(selector);
    if (el) {
        el.classList.toggle('expanded');
    }
}

// Keep old function for compatibility
function toggleTreeHost(hostEl) {
    const key = hostEl.dataset.key;
    if (key) {
        toggleTreeNode(key);
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

    // Format body based on content-type
    const formatBody = (body, headers = {}) => {
        if (!body || body.length === 0) return '<em>No body</em>';

        // Check if content is compressed
        const encoding = headers['content-encoding'] || '';
        if (encoding === 'br' || encoding === 'gzip' || encoding === 'deflate') {
            return `<em>Compressed data (${encoding}, ${body.length} bytes)</em>`;
        }

        const contentType = (headers['content-type'] || '').toLowerCase();

        // Check if it's a known binary type
        if (contentType.startsWith('image/') ||
            contentType.startsWith('audio/') ||
            contentType.startsWith('video/') ||
            contentType.includes('octet-stream') ||
            contentType.includes('pdf') ||
            contentType.includes('zip') ||
            contentType.includes('gzip')) {
            return `<em>Binary data (${contentType}, ${body.length} bytes)</em>`;
        }

        try {
            // Try to decode as text
            const text = typeof body === 'string' ? body : new TextDecoder().decode(new Uint8Array(body));

            // Check if it looks like binary (has many non-printable characters)
            const nonPrintable = text.split('').filter(c => {
                const code = c.charCodeAt(0);
                return code < 32 && code !== 9 && code !== 10 && code !== 13;
            }).length;

            if (nonPrintable > text.length * 0.1) {
                return `<em>Binary data (${body.length} bytes)</em>`;
            }

            // Format based on content-type
            if (contentType.includes('json')) {
                try {
                    const json = JSON.parse(text);
                    return `<pre class="body-json">${escapeHtml(JSON.stringify(json, null, 2))}</pre>`;
                } catch {
                    return `<pre class="body-text">${escapeHtml(text.substring(0, 50000))}</pre>`;
                }
            }

            if (contentType.includes('html')) {
                return `<pre class="body-html">${escapeHtml(text.substring(0, 50000))}</pre>`;
            }

            if (contentType.includes('xml')) {
                return `<pre class="body-xml">${escapeHtml(text.substring(0, 50000))}</pre>`;
            }

            if (contentType.includes('css')) {
                return `<pre class="body-css">${escapeHtml(text.substring(0, 50000))}</pre>`;
            }

            if (contentType.includes('javascript') || contentType.includes('ecmascript')) {
                return `<pre class="body-js">${escapeHtml(text.substring(0, 50000))}</pre>`;
            }

            // Default: plain text
            return `<pre class="body-text">${escapeHtml(text.substring(0, 50000))}</pre>`;
        } catch {
            return `<em>Binary data (${body.length} bytes)</em>`;
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
            ${entry.request.body && entry.request.body.length > 0 ? `
                <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Body (${formatSize(entry.request.body_size)})</h4>
                <div class="detail-body">${formatBody(entry.request.body, entry.request.headers)}</div>
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
                ${entry.response.body && entry.response.body.length > 0 ? `
                    <h4 style="margin: 1rem 0 0.5rem; font-size: 0.8rem; color: var(--text-secondary);">Body (${formatSize(entry.response.body_size)})</h4>
                    <div class="detail-body">${formatBody(entry.response.body, entry.response.headers)}</div>
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

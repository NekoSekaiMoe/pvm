document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const container = document.getElementById('sandbox-container');
    const activeCount = document.getElementById('active-count');

    // Theme logic
    themeToggle.addEventListener('click', () => {
        const isDark = document.body.getAttribute('data-theme') === 'dark';
        document.body.setAttribute('data-theme', isDark ? 'light' : 'dark');
        themeToggle.querySelector('span').innerText = isDark ? 'dark_mode' : 'light_mode';
    });

    // Mock API Data
    let sandboxes = [
        { id: 'sbx-7b2a9f', image: 'ubuntu:22.04', status: 'running', uptime: '1h 23m' },
        { id: 'sbx-4f1c8e', image: 'python:3.10-alpine', status: 'frozen', uptime: '2d 4h' },
        { id: 'sbx-9a3d2c', image: 'node:18-slim', status: 'stopped', uptime: '-' }
    ];

    const render = () => {
        container.innerHTML = '';
        let active = 0;
        sandboxes.forEach(sb => {
            if (sb.status === 'running') active++;
            const el = document.createElement('div');
            el.className = 'sandbox-item';
            
            // Icon logic
            let actionBtn = '';
            if (sb.status === 'running') {
                actionBtn = `<button class="md3-btn outlined" onclick="toggleStatus('${sb.id}')">
                                <span class="material-symbols-outlined">ac_unit</span> Freeze
                             </button>`;
            } else if (sb.status === 'frozen') {
                actionBtn = `<button class="md3-btn filled" onclick="toggleStatus('${sb.id}')">
                                <span class="material-symbols-outlined">play_arrow</span> Thaw
                             </button>`;
            } else {
                actionBtn = `<button class="md3-btn filled" onclick="toggleStatus('${sb.id}')">
                                <span class="material-symbols-outlined">rocket_launch</span> Start
                             </button>`;
            }

            el.innerHTML = `
                <div class="sandbox-info">
                    <div class="status-dot status-${sb.status}"></div>
                    <div>
                        <div style="font-weight: 500; font-size: 16px; margin-bottom: 4px">${sb.id}</div>
                        <div style="font-size: 14px; opacity: 0.7; display: flex; gap: 12px">
                            <span>📦 ${sb.image}</span>
                            <span>⏱️ ${sb.uptime}</span>
                        </div>
                    </div>
                </div>
                <div class="sandbox-actions">
                    ${actionBtn}
                    <button class="md3-icon-btn"><span class="material-symbols-outlined">more_vert</span></button>
                </div>
            `;
            container.appendChild(el);
        });
        activeCount.innerText = active;
    };

    window.toggleStatus = (id) => {
        const sb = sandboxes.find(s => s.id === id);
        if (sb.status === 'running') sb.status = 'frozen';
        else if (sb.status === 'frozen') sb.status = 'running';
        else if (sb.status === 'stopped') sb.status = 'running';
        render();
    };

    // Initial render
    render();
    
    // Setup FAB
    document.getElementById('fab-new').addEventListener('click', () => {
        const newId = 'sbx-' + Math.random().toString(16).slice(2,8);
        sandboxes.unshift({ id: newId, image: 'ubuntu:latest', status: 'running', uptime: '0m' });
        render();
    });
});

// popup.js — Phishing ONE v2.0

const DEFAULT_ENDPOINT = "http://localhost:5000/api/check_url";

document.addEventListener('DOMContentLoaded', async () => {

    // ── DOM refs ──────────────────────────────────────────
    const statusCard   = document.getElementById('status-card');
    const statusText   = document.getElementById('status-text');
    const urlText      = document.getElementById('url-text');
    const riskLevel    = document.getElementById('risk-level');
    const riskScore    = document.getElementById('risk-score');
    const reasonsList  = document.getElementById('reasons-list');
    const reasonsUl    = document.getElementById('reasons-ul');
    const engineBadge  = document.getElementById('engine-badge');

    // Settings panel
    const settingsBtn   = document.getElementById('settings-btn');
    const settingsPanel = document.getElementById('settings-panel');
    const endpointInput = document.getElementById('endpoint-input');
    const saveBtn       = document.getElementById('save-endpoint');
    const statusMsg     = document.getElementById('settings-status');
    const testBtn       = document.getElementById('test-connection');

    // ── Load saved endpoint ───────────────────────────────
    const { apiEndpoint } = await chrome.storage.local.get('apiEndpoint');
    const endpoint = apiEndpoint || DEFAULT_ENDPOINT;
    endpointInput.value = endpoint;

    // ── Settings toggle ───────────────────────────────────
    settingsBtn.addEventListener('click', () => {
        settingsPanel.classList.toggle('hidden');
    });

    saveBtn.addEventListener('click', async () => {
        const val = endpointInput.value.trim();
        if (!val) return;
        await chrome.storage.local.set({ apiEndpoint: val });
        statusMsg.textContent = "Saved!";
        statusMsg.style.color = "#10b981";
        setTimeout(() => { statusMsg.textContent = ""; }, 2000);
    });

    testBtn.addEventListener('click', async () => {
        const val = endpointInput.value.trim();
        statusMsg.textContent = "Testing...";
        statusMsg.style.color = "#94a3b8";
        try {
            const healthUrl = val.replace('/api/check_url', '/health');
            const res = await fetch(healthUrl, { method: 'GET' });
            if (res.ok) {
                const data = await res.json();
                const modelInfo = data.model_loaded
                    ? `✓ Connected — ${data.device || 'cpu'}`
                    : `✓ Connected (heuristic mode)`;
                statusMsg.textContent = modelInfo;
                statusMsg.style.color = "#10b981";
            } else {
                statusMsg.textContent = `✗ HTTP ${res.status}`;
                statusMsg.style.color = "#ef4444";
            }
        } catch {
            statusMsg.textContent = "✗ Unreachable — is Flask running?";
            statusMsg.style.color = "#ef4444";
        }
    });

    // ── Main scan ─────────────────────────────────────────
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
        setErrorState("Could not read tab URL.");
        return;
    }

    urlText.textContent = tab.url;

    if (!tab.url.startsWith("http")) {
        setNeutralState("Internal Page", "--", "N/A");
        return;
    }

    await checkUrl(tab.url, endpoint);

    // ── Functions ─────────────────────────────────────────
    async function checkUrl(url, ep) {
        try {
            const response = await fetch(ep, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const result = await response.json();
            updateUI(result);

        } catch (err) {
            setErrorState("Backend offline — start Flask and check ⚙️ settings.");
        }
    }

    function updateUI(result) {
        statusCard.classList.remove('loading');

        // Engine badge — shows "XLM-RoBERTa" or "Heuristic"
        if (engineBadge) {
            if (result.model_used === 'xlm-roberta') {
                const conf = result.confidence ? ` ${result.confidence}%` : '';
                engineBadge.textContent = `XLM-RoBERTa${conf}`;
                engineBadge.style.display = 'inline-block';
            } else if (result.model_used === 'heuristic') {
                engineBadge.textContent = 'Heuristic';
                engineBadge.style.display = 'inline-block';
            }
        }

        if (result.is_phishing) {
            statusCard.classList.add('danger');
            statusCard.classList.remove('safe');
            statusText.textContent = "Suspicious Site";
            riskLevel.textContent  = "High Risk";
            riskLevel.style.color  = "#ef4444";
            riskScore.textContent  = result.risk_score;

            if (result.reasons && result.reasons.length > 0) {
                reasonsList.classList.remove('hidden');
                reasonsUl.innerHTML = '';
                result.reasons.forEach(reason => {
                    const li = document.createElement('li');
                    li.textContent = reason;
                    reasonsUl.appendChild(li);
                });
            }
        } else {
            statusCard.classList.add('safe');
            statusCard.classList.remove('danger');
            statusText.textContent = "Verified Safe";
            riskLevel.textContent  = "Secure";
            riskLevel.style.color  = "#10b981";
            riskScore.textContent  = result.risk_score;
            reasonsList.classList.add('hidden');
        }
    }

    function setNeutralState(status, score, level) {
        statusCard.classList.remove('loading', 'danger', 'safe');
        statusText.textContent = status;
        riskScore.textContent  = score;
        riskLevel.textContent  = level;
    }

    function setErrorState(msg) {
        statusCard.classList.remove('loading', 'safe');
        statusCard.classList.add('danger');
        statusText.textContent = "Error";
        riskLevel.textContent  = "Offline";
        riskLevel.style.color  = "#ef4444";
        riskScore.textContent  = "!";
        urlText.textContent    = msg;
    }
});

// popup.js for Phishing ONE

const API_URL_ENDPOINT     = "http://localhost:5000/api/check_url";
const API_MESSAGE_ENDPOINT = "http://localhost:5000/api/check_message";

document.addEventListener('DOMContentLoaded', async () => {

    // ── Tab switching ────────────────────────────────────────────────────────
    const tabUrl   = document.getElementById('tab-url');
    const tabEmail = document.getElementById('tab-email');
    const panelUrl   = document.getElementById('panel-url');
    const panelEmail = document.getElementById('panel-email');

    tabUrl.addEventListener('click', () => {
        tabUrl.classList.add('active');
        tabEmail.classList.remove('active');
        panelUrl.classList.remove('hidden');
        panelEmail.classList.add('hidden');
    });

    tabEmail.addEventListener('click', () => {
        tabEmail.classList.add('active');
        tabUrl.classList.remove('active');
        panelEmail.classList.remove('hidden');
        panelUrl.classList.add('hidden');
    });

    // ── URL Tab ──────────────────────────────────────────────────────────────
    const statusCard  = document.getElementById('status-card');
    const statusText  = document.getElementById('status-text');
    const urlText     = document.getElementById('url-text');
    const riskLevel   = document.getElementById('risk-level');
    const riskScore   = document.getElementById('risk-score');
    const reasonsList = document.getElementById('reasons-list');
    const reasonsUl   = document.getElementById('reasons-ul');

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url) {
        urlText.textContent = tab.url;
        if (tab.url.startsWith("http")) {
            checkUrl(tab.url);
        } else {
            setSafeState("N/A", "--", "Internal Page");
        }
    } else {
        statusText.textContent = "Error";
        urlText.textContent = "Could not identify tab.";
    }

    async function checkUrl(url) {
        try {
            const response = await fetch(API_URL_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            if (!response.ok) throw new Error("Backend unreachable");
            const result = await response.json();
            updateUrlUI(result);
        } catch (error) {
            console.error(error);
            setSafeState("Error", "!!", "Backend Offline");
        }
    }

    function updateUrlUI(result) {
        statusCard.classList.remove('loading');
        if (result.is_phishing) {
            statusCard.classList.add('danger');
            statusText.textContent = "Suspicious Site";
            riskLevel.textContent = "High Risk";
            riskLevel.style.color = "#ef4444";
            riskScore.textContent = result.risk_score;
            reasonsList.classList.remove('hidden');
            reasonsUl.innerHTML = '';
            result.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                reasonsUl.appendChild(li);
            });
        } else {
            statusCard.classList.add('safe');
            statusText.textContent = "Verified Safe";
            riskLevel.textContent = "Secure";
            riskLevel.style.color = "#10b981";
            riskScore.textContent = result.risk_score ?? 0;
        }
    }

    function setSafeState(status, score, level) {
        statusCard.classList.remove('loading');
        statusText.textContent = status;
        riskScore.textContent = score;
        riskLevel.textContent = level;
    }

    // ── Email Tab ────────────────────────────────────────────────────────────
    const scanBtn          = document.getElementById('scan-btn');
    const emailInput       = document.getElementById('email-input');
    const emailStatusCard  = document.getElementById('email-status-card');
    const emailStatusIcon  = document.getElementById('email-status-icon');
    const emailStatusText  = document.getElementById('email-status-text');
    const emailConfidence  = document.getElementById('email-confidence');
    const emailReasonsList = document.getElementById('email-reasons-list');
    const emailReasonsUl   = document.getElementById('email-reasons-ul');

    scanBtn.addEventListener('click', async () => {
        const text = emailInput.value.trim();
        if (!text) return;

        // Loading state
        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning...";
        emailStatusCard.classList.add('hidden');
        emailReasonsList.classList.add('hidden');

        try {
            const response = await fetch(API_MESSAGE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text })
            });
            if (!response.ok) throw new Error("Backend unreachable");
            const result = await response.json();
            updateEmailUI(result);
        } catch (error) {
            console.error(error);
            emailStatusCard.classList.remove('hidden');
            emailStatusIcon.textContent = "⚠️";
            emailStatusText.textContent = "Backend Offline";
            emailConfidence.textContent = "Make sure app.py is running";
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = "🔍 Scan";
        }
    });

    function updateEmailUI(result) {
        emailStatusCard.classList.remove('hidden', 'safe', 'danger');

        if (result.is_phishing) {
            emailStatusCard.classList.add('danger');
            emailStatusIcon.textContent = "🚨";
            emailStatusText.textContent = "Phishing Detected";
            emailConfidence.textContent = result.confidence
                ? `${result.confidence}% confidence`
                : "High risk";

            emailReasonsList.classList.remove('hidden');
            emailReasonsUl.innerHTML = '';
            result.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                emailReasonsUl.appendChild(li);
            });
        } else {
            emailStatusCard.classList.add('safe');
            emailStatusIcon.textContent = "✅";
            emailStatusText.textContent = "Looks Safe";
            emailConfidence.textContent = result.confidence
                ? `${result.confidence}% confidence`
                : "Low risk";
            emailReasonsList.classList.add('hidden');
        }
    }
});
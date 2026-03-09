// popup.js for Phishing ONE

const API_ENDPOINT = "https://pulsatile-unmimeographed-deandrea.ngrok-free.dev/api/check_url";

document.addEventListener('DOMContentLoaded', async () => {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    const urlText = document.getElementById('url-text');
    const riskLevel = document.getElementById('risk-level');
    const riskScore = document.getElementById('risk-score');
    const reasonsList = document.getElementById('reasons-list');
    const reasonsUl = document.getElementById('reasons-ul');

    // Get current tab URL
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
            const response = await fetch(API_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) throw new Error("Backend unreachable");

            const result = await response.json();
            updateUI(result);
        } catch (error) {
            console.error(error);
            setSafeState("Error", "!!", "Backend Offline");
        }
    }

    function updateUI(result) {
        statusCard.classList.remove('loading');

        if (result.is_phishing) {
            statusCard.classList.add('danger');
            statusText.textContent = "Suspicious Site";
            riskLevel.textContent = "High Risk";
            riskLevel.style.color = "#ef4444";
            riskScore.textContent = result.risk_score;

            // Show reasons
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
            riskScore.textContent = result.risk_score;
        }
    }

    function setSafeState(status, score, level) {
        statusCard.classList.remove('loading');
        statusText.textContent = status;
        riskScore.textContent = score;
        riskLevel.textContent = level;
    }
});

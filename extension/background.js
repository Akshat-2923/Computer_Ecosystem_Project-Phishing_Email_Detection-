// background.js — Phishing ONE v2.0

const DEFAULT_ENDPOINT = "http://localhost:5000/api/check_url";

// On install, set the default endpoint if not already saved
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get('apiEndpoint', (data) => {
        if (!data.apiEndpoint) {
            chrome.storage.local.set({ apiEndpoint: DEFAULT_ENDPOINT });
        }
    });
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith("http")) {
        checkUrl(tab.url, tabId);
    }
});

async function checkUrl(url, tabId) {
    const { apiEndpoint } = await chrome.storage.local.get('apiEndpoint');
    const endpoint = apiEndpoint || DEFAULT_ENDPOINT;

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();

        if (result.is_phishing) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '⚠️ Phishing Warning!',
                message: `Phishing ONE flagged: ${url}\n${result.reasons.slice(0, 2).join(' · ')}`,
                priority: 2
            });
            chrome.action.setBadgeText({ text: "!", tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
        } else {
            chrome.action.setBadgeText({ text: "", tabId });
        }

    } catch (error) {
        console.error("[Phishing ONE] Backend unreachable:", error.message);
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#94a3b8", tabId });
    }
}

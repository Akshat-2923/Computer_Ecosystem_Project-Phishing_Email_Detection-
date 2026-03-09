
// background.js for Phishing ONE

const API_ENDPOINT = "https://pulsatile-unmimeographed-deandrea.ngrok-free.dev/api/check_url";

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only check when the status is 'complete' and we have a URL
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith("http")) {
        console.log("Checking URL:", tab.url);
        checkUrl(tab.url, tabId);
    }
});

async function checkUrl(url, tabId) {
    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        const result = await response.json();
        
        if (result.is_phishing) {
            console.warn("WARNING: Phishing detected!", result);
            
            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '⚠️ Phishing Warning!',
                message: `Phishing ONE has detected that ${url} might be a phishing site. Reasons: ${result.reasons.join(', ')}`,
                priority: 2
            });

            // Update icon badge or color (optional)
            chrome.action.setBadgeText({ text: "!", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId: tabId });
        } else {
            chrome.action.setBadgeText({ text: "", tabId: tabId });
        }
    } catch (error) {
        console.error("Error communicating with backend:", error);
    }
}

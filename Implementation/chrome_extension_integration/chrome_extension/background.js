//Background.js
let lastCheckedUrl = "";

// Check URL when a tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status === "complete" &&
    tab.url &&
    tab.url !== lastCheckedUrl
  ) {
    checkUrl(tab.url);
  }
});

// Check URL when switching tabs
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url && tab.url !== lastCheckedUrl) {
      checkUrl(tab.url);
    }
  });
});

function checkUrl(url) {
  lastCheckedUrl = url;
  fetch("http://127.0.0.1:5000/predict-url", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url: url }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      if (data.is_phishing) {
        chrome.action.setBadgeText({ text: "!" });
        chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
        chrome.storage.local.set({
          lastCheckedUrl: url,
          isPhishing: true,
          score: data.phishing_probability,
        });
      } else {
        chrome.action.setBadgeText({ text: "" });
        chrome.storage.local.set({
          lastCheckedUrl: url,
          isPhishing: false,
          score: data.phishing_probability,
        });
      }
    })
    .catch((error) => console.error("Error:", error));
}

// Initial check for the active tab when the extension is loaded
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0] && tabs[0].url) {
    checkUrl(tabs[0].url);
  }
});

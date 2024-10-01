// Popup.js
document.addEventListener("DOMContentLoaded", function () {
  chrome.storage.local.get(
    ["lastCheckedUrl", "isPhishing", "score"],
    function (result) {
      // URL
      const urlElement = document.getElementById("url");
      urlElement.textContent = result.lastCheckedUrl || "No URL checked yet";

      // Status
      const statusElement = document.getElementById("status");
      if (result.isPhishing) {
        statusElement.textContent = "Potential Phishing";
        statusElement.className = "danger";
      } else {
        statusElement.textContent = "Safe";
        statusElement.className = "safe";
      }

      // Score
      const scoreElement = document.getElementById("score");
      scoreElement.textContent = result.score
        ? (result.score * 100).toFixed(2) + "%"
        : "N/A";
    }
  );
});

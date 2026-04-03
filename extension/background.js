function analyzePageData(pageData, callback) {
  fetch("http://127.0.0.1:8000/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pageData)
  })
    .then(res => res.json())
    .then(result => {

      // Save result
      chrome.storage.local.set({ analysisResult: result }, () => {
        if (callback) callback(result);
      });

      // Get toggle state
      chrome.storage.local.get(["useWarning"], data => {

        const showWarning = data.useWarning !== false;

        // Send result + toggle state to content.js
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          if (tabs.length > 0) {
            chrome.tabs.sendMessage(tabs[0].id, {
              type: "ANALYSIS_RESULT",
              data: result,
              showWarning: showWarning
            });
          }
        });

      });

    })
    .catch(err => {
      console.error("Backend error", err);
      if (callback) callback(null);
    });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "PAGE_DATA") {
    analyzePageData(message.payload);
  }

  if (message.type === "REANALYZE_REQUEST") {

    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs.length) {
        sendResponse({ status: "FAILED" });
        return;
      }

      const tabId = tabs[0].id;

      chrome.tabs.sendMessage(
        tabId,
        { type: "REANALYZE_PAGE" },
        response => {

          if (response?.payload) {
            analyzePageData(response.payload, result => {
              sendResponse({ status: "DONE", result });
            });
          } else {
            sendResponse({ status: "FAILED" });
          }

        }
      );

    });

    return true;
  }

});
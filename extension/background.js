function analyzePageData(pageData, callback) {
  fetch("http://127.0.0.1:8000/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pageData)
  })
    .then(res => res.json())
    .then(result => {
      chrome.storage.local.set({ analysisResult: result }, () => {
        console.log("SafeSense: Analysis complete", result);
        if (callback) callback(result);
      });
    })
    .catch(err => {
      console.error("SafeSense: Backend error", err);
      if (callback) callback(null);
    });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "PAGE_DATA") {
    console.log("SafeSense: Auto page data received");
    analyzePageData(message.payload);
  }

  if (message.type === "REANALYZE_REQUEST") {
    console.log("SafeSense: Re-analyze button clicked");

    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs.length) {
        sendResponse({ status: "FAILED" });
        return;
      }

      const tabId = tabs[0].id;

      // 🔹 NEW: Capture screenshot if toggle enabled
      if (message.screenshot) {

        chrome.tabs.captureVisibleTab(null, { format: "png" }, dataUrl => {

          if (!dataUrl) {
            console.error("SafeSense: Screenshot failed");
            return;
          }

          const filename =
            "safesense_screenshot_" + Date.now() + ".png";

          chrome.downloads.download({
            url: dataUrl,
            filename: filename,
            saveAs: false
          });

          console.log("SafeSense: Screenshot saved");
        });

      }

      // Existing analysis flow
      chrome.tabs.sendMessage(
        tabId,
        { type: "REANALYZE_PAGE" },
        response => {

          console.log("SafeSense: Content script response", response);

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
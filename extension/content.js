function extractPageData() {
  const text = document.body.innerText.slice(0, 15000).toLowerCase();

  // Detect login form
  const hasPasswordField =
    document.querySelector('input[type="password"]') !== null;

  // Brand keyword detection
  const brandKeywords = ["instagram"];
  const detectedBrands = brandKeywords.filter(b => text.includes(b));

  return {
    text,
    url: window.location.href,
    hasPasswordField,
    detectedBrands
  };
}


// Initial analysis
chrome.runtime.sendMessage({
  type: "PAGE_DATA",
  payload: extractPageData()
});

// Re-analyze handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "REANALYZE_PAGE") {
    console.log("SafeSense: Re-analyze request received");
    sendResponse({ payload: extractPageData() });
  }
});

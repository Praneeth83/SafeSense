// -----------------------------
// Selector Generator
// -----------------------------
function getSelector(el) {
  if (el.id) return "#" + el.id;

  if (el.className) {
    const classes = el.className.split(" ").filter(c => c.trim() !== "");
    if (classes.length > 0) {
      return el.tagName.toLowerCase() + "." + classes[0];
    }
  }

  const parent = el.parentNode;
  if (!parent) return el.tagName.toLowerCase();

  const index = Array.from(parent.children).indexOf(el) + 1;
  return el.tagName.toLowerCase() + `:nth-child(${index})`;
}

// -----------------------------
// Detect Sensitive Fields
// -----------------------------
function getSensitiveFields(div) {
  const sensitiveSelectors = [
    "input[type='password']",
    "input[type='email']",
    "input[type='tel']",
    "input[name*='card']",
    "input[name*='cvv']",
    "input[name*='otp']",
    "input[name*='account']",
    "input[name*='bank']",
    "input[name*='upi']",
    "input[name*='aadhaar']",
    "input[name*='pan']"
  ];

  for (let selector of sensitiveSelectors) {
    if (div.querySelector(selector)) return true;
  }

  const text = div.innerText.toLowerCase();
  const keywords = [
    "password", "otp", "verification",
    "credit card", "debit card", "cvv",
    "bank account", "upi", "aadhaar",
    "pan", "login", "signin"
  ];

  return keywords.some(k => text.includes(k));
}

// -----------------------------
// Extract Div-Level Features
// -----------------------------
function getDivFeatures(div) {
  const inputs = div.querySelectorAll("input, textarea, select");
  const buttons = div.querySelectorAll("button");

  let hasPassword = false;
  let hasOTP = false;
  let hasCard = false;
  let hasFile = false;

  inputs.forEach(input => {
    const hint = (
      (input.name || "") +
      (input.id || "") +
      (input.placeholder || "") +
      (input.type || "")
    ).toLowerCase();

    const divText = div.innerText.toLowerCase();

    if (input.type === "password") hasPassword = true;
    if (input.type === "file") hasFile = true;
    if (hint.includes("otp") || divText.includes("otp")) hasOTP = true;
    if (hint.includes("card") || hint.includes("cvv")) hasCard = true;
  });

  return {
    numInputs: inputs.length,
    numButtons: buttons.length,
    hasPassword,
    hasOTP,
    hasCard,
    hasFile
  };
}

// -----------------------------
// Extract Page Data
// FIX: field names now match FastAPI's DivData model exactly
// -----------------------------
function extractPageData() {
  const pageText = document.body.innerText
    .replace("Dangerous Section Detected", "")
    .slice(0, 15000)
    .toLowerCase();

  const elements = Array.from(
    document.querySelectorAll("div, form, section")
  )
  .filter(el => !el.closest(".safesense-overlay"))
  .slice(0, 40);

  let divs = [];

  elements.forEach(el => {
    const text = el.innerText.trim().toLowerCase();

    if (text.length > 30) {
      const features = getDivFeatures(el);

      divs.push({
        text: text.slice(0, 2000),

        // FIX: these names now match DivData in main.py exactly
        hasPasswordField: features.hasPassword,
        hasSensitiveField: getSensitiveFields(el),
        numInputs: features.numInputs,
        hasFileUpload: features.hasFile,
        hasOTPField: features.hasOTP,
        hasCard: features.hasCard,

        selector: getSelector(el)
      });
    }
  });

  return {
    text: pageText,
    url: window.location.href,
    divs: divs
  };
}

// -----------------------------
// Danger Overlay UI
// -----------------------------
function createDangerOverlay(el) {
  el.style.position = "relative";

  const overlay = document.createElement("div");
  overlay.className = "safesense-overlay";

  overlay.style.cssText = `
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
    background: repeating-linear-gradient(
      45deg,
      rgba(255,0,0,0.25), rgba(255,0,0,0.25) 10px,
      rgba(255,0,0,0.35) 10px, rgba(255,0,0,0.35) 20px
    );
  `;

  overlay.innerHTML = `
    <div style="
      background: rgba(20,20,20,0.9);
      padding: 25px;
      border-radius: 12px;
      box-shadow: 0 0 25px rgba(255,0,0,0.6);
      text-align: center;
      max-width: 280px;
      border: 2px solid red;
      color: white;
      font-family: Arial;
    ">
      <div style="font-size:50px;">⚠</div>
      <div style="font-size:18px; font-weight:bold; color:#ff4d4d;">
        Dangerous Section
      </div>
      <div style="font-size:13px; margin:10px 0;">
        This section may try to steal your personal or financial information.
      </div>
      <button id="safesense-continue-btn" style="
        padding:8px 16px;
        border:none;
        background:red;
        color:white;
        border-radius:6px;
        cursor:pointer;
        font-weight:bold;
      ">
        Continue Anyway
      </button>
    </div>
  `;

  el.appendChild(overlay);
  overlay.querySelector("#safesense-continue-btn").onclick = () => overlay.remove();
}

// -----------------------------
// Highlight Only Innermost Risky Divs
// -----------------------------
function highlightRiskySelectors(selectors) {
  let elements = selectors
    .map(sel => {
      try { return document.querySelector(sel); }
      catch { return null; }
    })
    .filter(el => el !== null);

  // Only highlight innermost elements (not parents that contain other flagged els)
  let innerMost = elements.filter(el =>
    !elements.some(other => other !== el && el.contains(other))
  );

  document.querySelectorAll(".safesense-overlay").forEach(el => el.remove());
  innerMost.forEach(el => createDangerOverlay(el));
}

// -----------------------------
// Send Page Data on Load
// -----------------------------
chrome.runtime.sendMessage({
  type: "PAGE_DATA",
  payload: extractPageData()
});

// -----------------------------
// Listen for Messages from Background
// -----------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "REANALYZE_PAGE") {
    document.querySelectorAll(".safesense-overlay").forEach(el => el.remove());
    sendResponse({ payload: extractPageData() });
    return true;
  }

  else if (message.type === "ANALYSIS_RESULT") {
    document.querySelectorAll(".safesense-overlay").forEach(el => el.remove());

    if (!message.showWarning) return;

    const data = message.data;
    if (data.risky_selectors && data.risky_selectors.length > 0) {
      highlightRiskySelectors(data.risky_selectors);
    }
  }
});
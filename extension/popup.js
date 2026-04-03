const riskStatus = document.getElementById("riskStatus");
const triggersDiv = document.getElementById("triggers");
const reBtn = document.getElementById("reanalyzeBtn");
const screenshotToggle = document.getElementById("screenshotToggle");
const warningToggle = document.getElementById("warningToggle");

const circle = document.querySelector(".progress");
const circleText = document.getElementById("circleText");
const container = document.querySelector(".circleContainer");

const radius = 45;
const circumference = 2 * Math.PI * radius;

circle.style.strokeDasharray = circumference;
circle.style.strokeDashoffset = circumference;

/* ---------- LOADING ---------- */
function startLoading() {
  container.classList.add("loading");
  circle.style.strokeDasharray = "80 " + circumference;
  circle.style.strokeDashoffset = 0;
  circleText.innerText = "...";
}

/* ---------- ANIMATION ---------- */
function animateCircle(percent, color) {
  container.classList.remove("loading");

  circle.style.strokeDasharray = circumference;

  const start = performance.now();
  const duration = 500;

  function animate(time) {
    const progress = Math.min((time - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);

    const offset =
      circumference - eased * (percent / 100) * circumference;

    circle.style.strokeDashoffset = offset;

    const current = Math.round(eased * percent);
    circleText.innerText = current + "%";

    if (progress < 1) {
      requestAnimationFrame(animate);
    }
  }

  circle.style.stroke = color;
  requestAnimationFrame(animate);
}

/* ---------- RENDER ---------- */
function render(result) {
  if (!result) return;

  // IMPORTANT: USE FINAL RISK
  let score = Number(result.final_risk);
  if (isNaN(score)) score = 0;

  score = Math.max(0, Math.min(score, 1));
  const percent = Math.round(score * 100);

  let color;

  if (score > 0.7) {
    color = "#c62828";
    riskStatus.innerHTML = `
      <div class="status high">High Risk</div>
      <div class="subtext">High phishing / scam risk detected • ${percent}%</div>
    `;
  } 
  else if (score > 0.4) {
    color = "#f9a825";
    riskStatus.innerHTML = `
      <div class="status medium">Be Careful</div>
      <div class="subtext">Suspicious login / payment section detected • ${percent}%</div>
    `;
  } 
  else {
    color = "#2e7d32";
    riskStatus.innerHTML = `
      <div class="status low">Looks Safe</div>
      <div class="subtext">No major risk detected • ${percent}%</div>
    `;
  }

  animateCircle(percent, color);

  triggersDiv.innerHTML = "";

  if (result.triggers?.length) {
    triggersDiv.innerHTML =
      "<b>Detected phrases:</b><ul>" +
      result.triggers.map(t => `<li>${t}</li>`).join("") +
      "</ul>";
  }
}

/* ---------- LOAD ---------- */
chrome.storage.local.get(
  ["analysisResult", "useScreenshot", "useWarning"],
  data => {
    render(data.analysisResult);
    screenshotToggle.checked = data.useScreenshot || false;
    warningToggle.checked = data.useWarning ?? true;
  }
);

/* ---------- TOGGLES ---------- */
screenshotToggle.addEventListener("change", () => {
  chrome.storage.local.set({
    useScreenshot: screenshotToggle.checked
  });
});

warningToggle.addEventListener("change", () => {
  chrome.storage.local.set({
    useWarning: warningToggle.checked
  });
});

/* ---------- REANALYZE ---------- */
reBtn.addEventListener("click", () => {

  chrome.storage.local.remove("analysisResult");

  startLoading();
  riskStatus.innerHTML = `<div class="subtext">Analyzing page...</div>`;

  chrome.runtime.sendMessage(
    {
      type: "REANALYZE_REQUEST",
      screenshot: screenshotToggle.checked
    },
    (response) => {

      if (chrome.runtime.lastError) {
        riskStatus.innerHTML = `<div class="subtext">Extension error</div>`;
        return;
      }

      if (response?.status === "DONE" && response.result) {

        chrome.storage.local.set({
          analysisResult: response.result
        });

        render(response.result);

      } else {
        riskStatus.innerHTML = `<div class="subtext">Analysis failed</div>`;
      }

    }
  );
});

/* ---------- LISTENER ---------- */
chrome.storage.onChanged.addListener((changes) => {
  if (changes.analysisResult) {
    render(changes.analysisResult.newValue);
  }
});
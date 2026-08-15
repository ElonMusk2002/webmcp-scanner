// Runs in the ISOLATED world (default for content_scripts) — has chrome.runtime
// access, unlike the MAIN-world inject.js. Its only job is bridging the DOM
// CustomEvent from inject.js over to the popup via extension messaging.
document.addEventListener("__webmcp_scan_done", (e) => {
  chrome.runtime.sendMessage({ type: "WEBMCP_SCAN_RESULT", payload: e.detail });
});

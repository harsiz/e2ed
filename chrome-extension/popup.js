/*
 * popup.js
 * Handles the "Forget All Passwords" button. The popup runs in the
 * extension's own context and cannot reach a page's localStorage directly, so
 * chrome.scripting.executeScript is used to run a tiny function inside the
 * active Discord tab's MAIN world (the same world chrome-app.js runs in) that
 * clears e2ed's stored passwords and reloads the page.
 */

(function () {
  "use strict";

  var STORAGE_KEY = "e2ed_channels_v1";
  var btn = document.getElementById("forget-btn");
  var status = document.getElementById("forget-status");

  function setStatus(text) {
    status.textContent = text;
  }

  btn.addEventListener("click", function () {
    btn.disabled = true;
    setStatus("Working...");

    chrome.tabs.query(
      { active: true, currentWindow: true, url: ["https://discord.com/*", "https://*.discord.com/*"] },
      function (tabs) {
        var tab = tabs && tabs[0];
        if (!tab) {
          btn.disabled = false;
          setStatus("Open Discord in the current tab first.");
          return;
        }

        chrome.scripting.executeScript(
          {
            target: { tabId: tab.id },
            world: "MAIN",
            func: function (key) {
              localStorage.removeItem(key);
            },
            args: [STORAGE_KEY],
          },
          function () {
            btn.disabled = false;
            if (chrome.runtime.lastError) {
              setStatus("Could not clear passwords: " + chrome.runtime.lastError.message);
              return;
            }
            setStatus("All saved passwords forgotten. Reloading Discord...");
            chrome.tabs.reload(tab.id);
          }
        );
      }
    );
  });
})();

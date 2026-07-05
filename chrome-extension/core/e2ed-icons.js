/*
 * e2ed-icons.js
 * Inline SVG markup for the lock states, shared by both clients. The paths are
 * drawn to match Discord's 24x24 icon grid so they sit naturally in the toolbar.
 */

(function (root) {
  "use strict";

  // Closed padlock (armed, outgoing text is encrypted).
  var LOCK_CLOSED =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm3 8H9V7a3 3 0 1 1 6 0v3Zm-3 4a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
    "</svg>";

  // Open padlock (password set but disarmed, outgoing text is plaintext).
  var LOCK_OPEN =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5 1 1 0 0 0 2 0 3 3 0 1 1 6 0v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm0 12a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
    "</svg>";

  // Key (no password set yet for this channel).
  var KEY =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M14.5 2a5.5 5.5 0 0 0-5.4 6.53L2 15.63V20a1 1 0 0 0 1 1h4.5a1 1 0 0 0 1-1v-1.5H10a1 1 0 0 0 1-1V16h1.5a1 1 0 0 0 .71-.29l1.36-1.36A5.5 5.5 0 1 0 14.5 2Zm2 5.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Z"/>' +
    "</svg>";

  function iconForState(state) {
    if (state === "on") return LOCK_CLOSED;
    if (state === "off") return LOCK_OPEN;
    return KEY;
  }

  root.E2EDIcons = {
    LOCK_CLOSED: LOCK_CLOSED,
    LOCK_OPEN: LOCK_OPEN,
    KEY: KEY,
    iconForState: iconForState,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.E2EDIcons;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);

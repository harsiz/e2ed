/*
 * e2ed-core.js
 * Shared cryptography and wire-protocol logic for e2ed (End to End for Discord).
 *
 * This file is environment agnostic. It attaches a single object, `E2EDCore`,
 * to `globalThis` so it can be reused by both the Chrome content script and the
 * BetterDiscord plugin without a bundler. Everything relies on the standard
 * Web Crypto API, which is available in every context Discord runs in.
 *
 * Design overview
 * ---------------
 *  - Both parties agree on a shared password out of band (in person, over the
 *    phone, in a different app, etc.) for a given conversation. e2ed never
 *    transmits this password anywhere.
 *  - Each side derives an identical AES-256-GCM key from that password with
 *    PBKDF2, salted with the channel id so the same password produces a
 *    different key in every conversation. Because both sides derive the key
 *    locally from the same input, there is no handshake and nothing to race:
 *    the keys always match as long as the password matches.
 *  - Message bodies are encrypted with AES-GCM (random 12 byte IV) and encoded
 *    as text so they survive Discord's plain-text message field. Emoji (custom
 *    and unicode), ascii and any other unicode all round-trip because we
 *    operate on UTF-8 bytes, not code points.
 *
 * Only text messages are handled. Attachments and files are intentionally out
 * of scope and are never encrypted or decrypted by e2ed.
 *
 * Note on trust: a password known to both people is only as secret as the
 * channel it was shared over. Treat it like any shared secret and pick
 * something the two of you have not posted anywhere public.
 */

(function (root) {
  "use strict";

  var crypto = root.crypto || root.msCrypto;
  var subtle = crypto && crypto.subtle;

  var CIPHER_PREFIX = "e2ed:1:"; // followed by base64url(iv || ciphertext)
  var PBKDF2_ITERATIONS = 200000;

  // ---- byte / text helpers -------------------------------------------------

  var textEncoder = new root.TextEncoder();
  var textDecoder = new root.TextDecoder();

  function toBytes(str) {
    return textEncoder.encode(str);
  }

  function fromBytes(bytes) {
    return textDecoder.decode(bytes);
  }

  function bufToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    var b64 = root.btoa(binary);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64urlToBuf(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) {
      b64 += "=";
    }
    var binary = root.atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function concatBytes(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // ---- password based key derivation ---------------------------------------

  /*
   * Derive the shared AES-GCM key straight from a password both parties agreed
   * on out of band. Salting with the channel id means the same password used
   * in two different conversations still produces two different keys.
   */
  function deriveKeyFromPassword(password, channelId) {
    var normalized = String(password).trim();
    return subtle
      .importKey("raw", toBytes(normalized), { name: "PBKDF2" }, false, [
        "deriveKey",
      ])
      .then(function (keyMaterial) {
        return subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: toBytes("e2ed-pwd-salt-v1:" + channelId),
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
      });
  }

  /*
   * A short, human comparable code derived from the password and channel id.
   * Lets both people confirm they typed the exact same password without
   * revealing it, similar in spirit to a safety number.
   */
  function passwordFingerprint(password, channelId) {
    var normalized = String(password).trim();
    return subtle
      .digest("SHA-256", toBytes(channelId + "|" + normalized))
      .then(function (digest) {
        var bytes = new Uint8Array(digest).slice(0, 6);
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
          var h = bytes[i].toString(16);
          hex += (h.length === 1 ? "0" : "") + h;
        }
        return hex.match(/.{1,4}/g).join(" ");
      });
  }

  // ---- message framing -----------------------------------------------------

  function isEncrypted(content) {
    return typeof content === "string" && content.indexOf(CIPHER_PREFIX) === 0;
  }

  function encrypt(sharedKey, plaintext) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var data = toBytes(plaintext);
    return subtle
      .encrypt({ name: "AES-GCM", iv: iv }, sharedKey, data)
      .then(function (cipherBuffer) {
        var packed = concatBytes(iv, new Uint8Array(cipherBuffer));
        return CIPHER_PREFIX + bufToBase64url(packed);
      });
  }

  function decrypt(sharedKey, content) {
    if (!isEncrypted(content)) {
      return root.Promise.reject(new Error("not an e2ed message"));
    }
    var packed = base64urlToBuf(content.slice(CIPHER_PREFIX.length));
    var iv = packed.slice(0, 12);
    var cipher = packed.slice(12);
    return subtle
      .decrypt({ name: "AES-GCM", iv: iv }, sharedKey, cipher)
      .then(function (plainBuffer) {
        return fromBytes(new Uint8Array(plainBuffer));
      });
  }

  var E2EDCore = {
    CIPHER_PREFIX: CIPHER_PREFIX,
    deriveKeyFromPassword: deriveKeyFromPassword,
    passwordFingerprint: passwordFingerprint,
    isEncrypted: isEncrypted,
    encrypt: encrypt,
    decrypt: decrypt,
  };

  root.E2EDCore = E2EDCore;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = E2EDCore;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);

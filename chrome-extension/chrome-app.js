/*
 * chrome-app.js
 * Chrome (MV3) content script for e2ed, running in the MAIN world so it can
 * read Discord's own theme variables and interact with its message box the
 * same way a real user would.
 *
 * Key agreement is password based: both parties agree on a password out of
 * band for a given conversation, and each side derives an identical AES key
 * locally with PBKDF2. There is no handshake message and nothing to race, so
 * the two clients always end up with the same key as long as the password
 * matches. See core/e2ed-core.js for the derivation.
 *
 * Outgoing text is encrypted by hooking both `window.fetch` and
 * `XMLHttpRequest` and swapping the `content` field of outgoing POSTs to
 * Discord's messages endpoint for ciphertext, then letting Discord's own
 * client send the (now modified) request exactly as it normally would.
 * (Both are hooked because Discord sends some requests via each, and message
 * sends in particular go through XHR in current builds, so a fetch-only hook
 * silently missed them.) Three other approaches were tried and abandoned:
 *   - Patching Discord's MessageActions.sendMessage pulled out of its webpack
 *     module cache: Discord's web client is split across several independent
 *     webpack builds and routes sends through an internal queue, making the
 *     right module hard to find reliably and liable to break on any deploy.
 *   - Blocking the real Enter and re-dispatching a fake one: any event a
 *     script creates always has `isTrusted: false`, and Discord's send
 *     handling ignores untrusted key events, so nothing was ever sent.
 *   - Blocking the real Enter, sending the ciphertext ourselves via a direct
 *     POST, and then clearing the message box manually (via
 *     `execCommand("selectAll")` + insert, or a manually built Range): both
 *     corrupt Discord's Slate editor internal model (visible in the console
 *     as "Cannot resolve a Slate point from DOM point" errors), leaving the
 *     box broken for everything typed afterwards, including with e2ed turned
 *     back off. Slate's DOM structure and its own reconciliation logic are
 *     not something a content script can safely drive from outside.
 *   - Hooking `window.fetch` was tried first too, but failed at that time
 *     because the content script ran at "document_idle", after Discord's
 *     bundle had already grabbed its own reference to the native `fetch`.
 *     That reason no longer applies now that this script runs at
 *     "document_start" (see manifest.json): the hook installs before
 *     Discord's own script even runs, so any reference Discord's bundle takes
 *     to `fetch` during its own initialization is already our wrapped
 *     version. This approach only touches the outgoing network request, never
 *     Discord's editor, so it carries none of the Slate corruption risk.
 *
 * Because Discord's own client performs the actual send (with our ciphertext
 * substituted into the body), it clears its own message box exactly the way
 * it always does, so nothing else about the compose box has to be touched.
 *
 * Because document.body does not exist yet at document_start, anything that
 * needs it (the MutationObserver used for decrypting incoming messages) waits
 * for it via whenBodyReady() below.
 *
 * Responsibilities:
 *   - Own the SessionManager (per channel password derived key + armed toggle).
 *   - Persist passwords locally (this page's localStorage) so they survive reloads.
 *   - Encrypt outgoing text by rewriting the body of Discord's own outgoing
 *     send request, but only while the channel is armed (lock is green).
 *   - Decrypt incoming text by observing the DOM, retrying on every sweep until
 *     a key is available, so any number of already-rendered encrypted messages
 *     get decrypted as soon as the password is set.
 *   - Render the native looking lock toggle and status banner with an inline
 *     password form.
 *
 * Text messages only. Attachments/files are never touched by e2ed.
 */

(function () {
  "use strict";

  var Core = globalThis.E2EDCore;
  var Icons = globalThis.E2EDIcons;
  var session = new globalThis.E2EDSession();

  var STORAGE_KEY = "e2ed_channels_v1";

  function currentChannelId() {
    // Discord routes look like /channels/@me/<id> or /channels/<guild>/<id>.
    var m = location.pathname.match(/\/channels\/[^/]+\/(\d+)/);
    return m ? m[1] : null;
  }

  // ---- local persistence (page localStorage; never transmitted) -----------
  // Passwords are stored only in this browser's localStorage for discord.com,
  // never sent anywhere by e2ed. Treat a compromised browser/extension as a
  // risk to any password stored this way, same as any other local secret.

  function loadStore() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    } catch (e) {
      return {};
    }
  }

  function saveStore(store) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
    } catch (e) {
      /* ignore quota errors */
    }
  }

  function persistPassword(channelId, password, armed) {
    var store = loadStore();
    store[channelId] = { password: password, armed: armed };
    saveStore(store);
  }

  function persistArmed(channelId, armed) {
    var store = loadStore();
    if (store[channelId]) {
      store[channelId].armed = armed;
      saveStore(store);
    }
  }

  function restoreAll() {
    var store = loadStore();
    var ids = Object.keys(store);
    return Promise.all(
      ids.map(function (channelId) {
        var entry = store[channelId];
        return session.restore(channelId, entry.password, entry.armed);
      })
    );
  }

  // ---- outgoing: rewrite Discord's own send request ------------------------

  // e2ed only ever intercepts one specific thing: a POST to Discord's own
  // "send a message" endpoint, and only for a channel whose lock is currently
  // green (armed). Anything else, including every request while e2ed is off,
  // is handed straight to Discord's native function untouched: no parsing, no
  // encryption, no tracking, exactly the default Discord behavior.
  //
  // Both fetch and XHR are wrapped because Discord's web client sends some
  // requests through each, and message sends in particular go through XHR in
  // current builds (a fetch-only hook silently missed them). The wrappers are
  // installed at document_start (see manifest.json) so they are in place
  // before Discord's bundle grabs its own reference to these functions; a hook
  // installed later would never be called.

  var MESSAGES_RE = /\/api\/v\d+\/channels\/(\d+)\/messages(?:$|\?)/;

  function channelIdFromUrl(url) {
    var m = String(url).match(MESSAGES_RE);
    return m ? m[1] : null;
  }

  // Given a channel id and a JSON request body string, returns a Promise of a
  // rewritten body string with encrypted content, or null if this request
  // should be left completely untouched (not armed, no content, already
  // encrypted, unparseable, etc). Returning null is the "do nothing" path.
  function maybeEncryptBody(channelId, bodyString) {
    if (!channelId || !session.canEncrypt(channelId) || typeof bodyString !== "string") {
      return null;
    }
    var payload;
    try {
      payload = JSON.parse(bodyString);
    } catch (e) {
      return null;
    }
    if (
      !payload ||
      typeof payload.content !== "string" ||
      payload.content.length === 0 ||
      Core.isEncrypted(payload.content)
    ) {
      return null;
    }
    return session.encrypt(channelId, payload.content).then(function (cipher) {
      payload.content = cipher;
      return JSON.stringify(payload);
    });
  }

  // fetch wrapper.
  var nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var channelId = null;
    var method = "GET";
    try {
      var url = typeof input === "string" ? input : input && input.url;
      method = (init && init.method) || (input && input.method) || "GET";
      channelId = channelIdFromUrl(url);
    } catch (e) {
      return nativeFetch(input, init);
    }

    // Off / not a message send: pure passthrough, nothing runs.
    if (!channelId || String(method).toUpperCase() !== "POST" || !init) {
      return nativeFetch(input, init);
    }
    var rewrite = maybeEncryptBody(channelId, init.body);
    if (!rewrite) {
      return nativeFetch(input, init);
    }
    return rewrite
      .then(function (newBody) {
        return nativeFetch(input, Object.assign({}, init, { body: newBody }));
      })
      .catch(function (err) {
        console.warn("[e2ed] encryption failed, message not modified", err);
        return nativeFetch(input, init);
      });
  };

  // XHR wrapper. open() records the method and url on the instance so send()
  // can decide; send() defers the real send until encryption resolves.
  var nativeOpen = XMLHttpRequest.prototype.open;
  var nativeSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__e2ed = { method: method, url: url };
    return nativeOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    var info = this.__e2ed;
    var channelId = info && channelIdFromUrl(info.url);

    // Off / not a message send: pure passthrough, nothing runs.
    if (!channelId || !info || String(info.method).toUpperCase() !== "POST") {
      return nativeSend.apply(this, arguments);
    }
    var rewrite = maybeEncryptBody(channelId, body);
    if (!rewrite) {
      return nativeSend.apply(this, arguments);
    }
    var xhr = this;
    var originalArgs = arguments;
    rewrite
      .then(function (newBody) {
        nativeSend.call(xhr, newBody);
      })
      .catch(function (err) {
        console.warn("[e2ed] encryption failed, message not modified", err);
        nativeSend.apply(xhr, originalArgs);
      });
  };

  // ---- incoming: observe DOM ------------------------------------------------

  // Discord renders message text inside elements matching id^="message-content-".
  // Each element progresses through statuses: (none) -> "pending" -> "decrypted".
  // "pending" messages are retried on every sweep, which is how any number of
  // already visible encrypted messages get decrypted once a key becomes known.
  function processMessageNode(node) {
    if (!node || !node.querySelectorAll) {
      return;
    }
    var contents =
      node.matches && node.matches('[id^="message-content-"]')
        ? [node]
        : node.querySelectorAll('[id^="message-content-"]');

    contents.forEach(function (el) {
      if (el.dataset.e2edStatus === "decrypted" || el.dataset.e2edStatus === "skip") {
        return;
      }

      if (!el.dataset.e2edStatus) {
        var text = el.textContent || "";
        if (!Core.isEncrypted(text)) {
          el.dataset.e2edStatus = "skip";
          return;
        }
        el.dataset.e2edCipher = text;
        el.dataset.e2edStatus = "pending";
        showPendingPlaceholder(el);
      }

      var channelId = currentChannelId();
      if (channelId && session.canDecrypt(channelId)) {
        session
          .decrypt(channelId, el.dataset.e2edCipher)
          .then(function (plain) {
            renderDecrypted(el, plain);
            el.dataset.e2edStatus = "decrypted";
          })
          .catch(function () {
            /* still pending; will retry on next sweep */
          });
      }
    });
  }

  function showPendingPlaceholder(el) {
    el.textContent = "";
    var lock = document.createElement("span");
    lock.className = "e2ed-banner-icon";
    lock.innerHTML = Icons.LOCK_CLOSED;
    var note = document.createElement("span");
    note.className = "e2ed-file-notice";
    note.textContent = " Encrypted message (enter the shared password to read it)";
    el.appendChild(lock);
    el.appendChild(note);
  }

  function renderDecrypted(el, plaintext) {
    el.textContent = plaintext;
    var tag = document.createElement("span");
    tag.className = "e2ed-decrypted-tag";
    tag.innerHTML = Icons.LOCK_CLOSED + "e2ed";
    el.appendChild(tag);
  }

  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var added = mutations[i].addedNodes;
      for (var j = 0; j < added.length; j++) {
        if (added[j].nodeType === 1) {
          processMessageNode(added[j]);
        }
      }
    }
  });

  // The script runs at document_start (see manifest.json) so the Enter-key
  // interceptor below registers before Discord's own page scripts do, but
  // that means document.body does not exist yet at this point.
  function whenBodyReady(cb) {
    if (document.body) {
      cb();
      return;
    }
    var readyObserver = new MutationObserver(function () {
      if (document.body) {
        readyObserver.disconnect();
        cb();
      }
    });
    readyObserver.observe(document.documentElement, { childList: true });
  }

  whenBodyReady(function () {
    observer.observe(document.body, { childList: true, subtree: true });
  });

  // Sweep re-checks everything currently rendered, retrying any message still
  // marked "pending" (no key was available last time it was checked).
  function sweep() {
    processMessageNode(document.body);
  }

  // ---- UI: lock toggle + banner ---------------------------------------------

  var uiState = {}; // channelId -> { formOpen }

  function uiFor(channelId) {
    if (!uiState[channelId]) {
      uiState[channelId] = { formOpen: false };
    }
    return uiState[channelId];
  }

  function stateLabel(state) {
    return state === "on"
      ? "End to end encrypted. Messages you send are encrypted."
      : state === "off"
      ? "e2ed is off. Messages you send are plaintext."
      : "No shared password set for this conversation yet.";
  }

  function ensureLockButton() {
    // Scoped to the message compose form specifically: a bare
    // `[class*="buttons_"]` match also matches the user panel's mute/deafen/
    // settings toolbar at the bottom left, which happens to appear earlier in
    // the DOM, and crowds the lock button in among the wrong icons.
    var form = document.querySelector('form[class*="form_"]');
    var toolbar = form ? form.querySelector('[class*="buttons_"]') : null;
    if (!toolbar) {
      return;
    }
    var btn = document.getElementById("e2ed-lock-btn");
    if (!btn) {
      btn = document.createElement("button");
      btn.id = "e2ed-lock-btn";
      btn.className = "e2ed-lock-btn";
      btn.type = "button";
      btn.addEventListener("click", onLockClick);
      toolbar.insertBefore(btn, toolbar.firstChild);
    } else if (btn.parentNode !== toolbar) {
      // Move a button left over from before the toolbar scoping fix.
      toolbar.insertBefore(btn, toolbar.firstChild);
    }
    var state = session.getState(currentChannelId());
    btn.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    btn.classList.add("e2ed-" + state);
    btn.title = stateLabel(state);
    btn.innerHTML = Icons.iconForState(state);
  }

  function onLockClick() {
    var channelId = currentChannelId();
    if (!channelId) {
      return;
    }
    if (!session.hasKey(channelId)) {
      uiFor(channelId).formOpen = true;
      refreshUi();
      focusPasswordInput();
      return;
    }
    var newState = session.toggle(channelId);
    if (newState) {
      persistArmed(channelId, newState === "on");
    }
    refreshUi();
  }

  function focusPasswordInput() {
    var input = document.getElementById("e2ed-pw-input");
    if (input) {
      input.focus();
    }
  }

  function onSubmitPassword(channelId) {
    var input = document.getElementById("e2ed-pw-input");
    if (!input || !input.value) {
      return;
    }
    var password = input.value;
    session.setPassword(channelId, password).then(function () {
      persistPassword(channelId, password, true);
      uiFor(channelId).formOpen = false;
      refreshUi();
      sweep();
    });
  }

  function ensureBanner() {
    var channelId = currentChannelId();
    if (!channelId) {
      return;
    }
    var form = document.querySelector('form[class*="form_"]');
    if (!form) {
      return;
    }
    var banner = document.getElementById("e2ed-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "e2ed-banner";
      banner.className = "e2ed-banner";
      form.parentNode.insertBefore(banner, form);
    }

    var state = session.getState(channelId);
    var fp = session.getConfirmation(channelId);
    var ui = uiFor(channelId);

    // Skip rebuilding the DOM if nothing relevant changed and the password
    // field currently has focus, so typing is never interrupted by a tick.
    var signature = channelId + "|" + state + "|" + fp + "|" + ui.formOpen;
    var pwHasFocus = document.activeElement && document.activeElement.id === "e2ed-pw-input";
    if (banner.dataset.e2edSig === signature && pwHasFocus) {
      return;
    }
    banner.dataset.e2edSig = signature;

    banner.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    banner.classList.add("e2ed-" + state);

    var actionHtml = "";
    if (state !== "no-key") {
      actionHtml =
        ' <button type="button" class="e2ed-banner-action" id="e2ed-change-pw">Change password</button>';
    }
    var fpHtml = fp
      ? '<span class="e2ed-banner-fp" title="Password confirmation code">' +
        fp +
        "</span>"
      : "";

    var rowHtml =
      '<div class="e2ed-banner-row"><span class="e2ed-banner-icon">' +
      Icons.iconForState(state) +
      "</span><span>" +
      stateLabel(state) +
      " Files are not supported (text only)." +
      actionHtml +
      "</span>" +
      fpHtml +
      "</div>";

    var formHtml = "";
    if (state === "no-key" || ui.formOpen) {
      formHtml =
        '<div class="e2ed-pw-form">' +
        '<input type="password" id="e2ed-pw-input" class="e2ed-pw-input" ' +
        'placeholder="Shared password for this conversation" autocomplete="off" />' +
        '<button type="button" class="e2ed-pw-submit" id="e2ed-pw-submit">Set</button>' +
        "</div>";
    }

    banner.innerHTML = rowHtml + formHtml;

    var submitBtn = document.getElementById("e2ed-pw-submit");
    if (submitBtn) {
      submitBtn.addEventListener("click", function () {
        onSubmitPassword(channelId);
      });
    }
    var pwInput = document.getElementById("e2ed-pw-input");
    if (pwInput) {
      pwInput.addEventListener("keydown", function (evt) {
        if (evt.key === "Enter") {
          evt.preventDefault();
          onSubmitPassword(channelId);
        }
      });
    }
    var changeBtn = document.getElementById("e2ed-change-pw");
    if (changeBtn) {
      changeBtn.addEventListener("click", function () {
        ui.formOpen = true;
        refreshUi();
        focusPasswordInput();
      });
    }
  }

  function refreshUi() {
    ensureLockButton();
    ensureBanner();
  }

  // ---- lifecycle ------------------------------------------------------------

  restoreAll().then(function () {
    refreshUi();
    sweep();
  });

  // Re-render UI and rescan when the user switches channels or Discord re-renders.
  setInterval(function () {
    refreshUi();
    sweep();
  }, 1500);
})();

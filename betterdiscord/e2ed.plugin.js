/**
 * @name e2ed
 * @author harsiz
 * @description Simple end to end encryption for Discord DMs and server messages. Both parties need e2ed installed. Text only, no files.
 * @version 2.0.0
 * @source https://github.com/harsiz/e2ed
 * @website https://github.com/harsiz/e2ed
 */

/*
 * BetterDiscord build of e2ed. Single file by necessity, so the crypto core is
 * inlined below (kept in step with core/e2ed-core.js and core/e2ed-session.js).
 *
 * Key agreement is password based: both parties agree on a password out of
 * band for a given conversation, and each side derives an identical AES key
 * locally with PBKDF2, salted with the channel id. There is no handshake
 * message and nothing to race, so the two clients always end up with the same
 * key as long as the password matches.
 *
 * Outgoing text is encrypted by patching MessageActions.sendMessage, but only
 * while the channel is armed (lock is green). Incoming text is decrypted, with
 * retries on every sweep, by observing the DOM. Files/attachments are never
 * touched.
 */

module.exports = class E2ED {
  constructor() {
    this.observer = null;
    this.uiTimer = null;
    this.unpatch = null;
    this.uiState = {};
  }

  // ---- inlined crypto core (mirror of core/e2ed-core.js) ------------------

  buildCore() {
    const subtle = crypto.subtle;
    const CIPHER_PREFIX = "e2ed:1:";
    const PBKDF2_ITERATIONS = 200000;
    const te = new TextEncoder();
    const td = new TextDecoder();

    const toBytes = (s) => te.encode(s);
    const fromBytes = (b) => td.decode(b);

    const b64url = (buf) => {
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };
    const unb64url = (s) => {
      let b = s.replace(/-/g, "+").replace(/_/g, "/");
      while (b.length % 4) b += "=";
      const bin = atob(b);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    };
    const concat = (a, b) => {
      const o = new Uint8Array(a.length + b.length);
      o.set(a, 0);
      o.set(b, a.length);
      return o;
    };

    return {
      CIPHER_PREFIX,
      deriveKeyFromPassword: (password, channelId) => {
        const normalized = String(password).trim();
        return subtle
          .importKey("raw", toBytes(normalized), { name: "PBKDF2" }, false, ["deriveKey"])
          .then((keyMaterial) =>
            subtle.deriveKey(
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
            )
          );
      },
      passwordFingerprint: (password, channelId) => {
        const normalized = String(password).trim();
        return subtle.digest("SHA-256", toBytes(channelId + "|" + normalized)).then((d) => {
          const bytes = new Uint8Array(d).slice(0, 6);
          let hex = "";
          for (let i = 0; i < bytes.length; i++) {
            const h = bytes[i].toString(16);
            hex += (h.length === 1 ? "0" : "") + h;
          }
          return hex.match(/.{1,4}/g).join(" ");
        });
      },
      isEncrypted: (c) => typeof c === "string" && c.indexOf(CIPHER_PREFIX) === 0,
      encrypt: (key, text) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        return subtle
          .encrypt({ name: "AES-GCM", iv }, key, toBytes(text))
          .then((cb) => CIPHER_PREFIX + b64url(concat(iv, new Uint8Array(cb))));
      },
      decrypt: (key, content) => {
        const packed = unb64url(content.slice(CIPHER_PREFIX.length));
        const iv = packed.slice(0, 12);
        const cipher = packed.slice(12);
        return subtle
          .decrypt({ name: "AES-GCM", iv }, key, cipher)
          .then((pb) => fromBytes(new Uint8Array(pb)));
      },
    };
  }

  // ---- inlined session state (mirror of core/e2ed-session.js) -------------

  buildSession(Core) {
    const channels = {}; // channelId -> { key, armed, confirmation }
    const ch = (id) => {
      if (!channels[id]) channels[id] = { key: null, armed: false, confirmation: null };
      return channels[id];
    };
    const getState = (id) => {
      const c = channels[id];
      if (!c || !c.key) return "no-key";
      return c.armed ? "on" : "off";
    };
    return {
      hasKey: (id) => !!(channels[id] && channels[id].key),
      getState,
      getConfirmation: (id) => (channels[id] ? channels[id].confirmation : null),
      setPassword(id, password) {
        const c = ch(id);
        return Core.deriveKeyFromPassword(password, id)
          .then((key) => {
            c.key = key;
            c.armed = true;
            return Core.passwordFingerprint(password, id);
          })
          .then((fp) => {
            c.confirmation = fp;
            return { state: getState(id), confirmation: fp };
          });
      },
      restore(id, password, armed) {
        const c = ch(id);
        return Core.deriveKeyFromPassword(password, id)
          .then((key) => {
            c.key = key;
            c.armed = !!armed;
            return Core.passwordFingerprint(password, id);
          })
          .then((fp) => {
            c.confirmation = fp;
            return getState(id);
          });
      },
      toggle(id) {
        const c = channels[id];
        if (!c || !c.key) return null;
        c.armed = !c.armed;
        return getState(id);
      },
      isArmed: (id) => !!(channels[id] && channels[id].armed && channels[id].key),
      canEncrypt(id) {
        return this.isArmed(id);
      },
      canDecrypt: (id) => !!(channels[id] && channels[id].key),
      encrypt(id, text) {
        const c = channels[id];
        if (!c || !c.key) return Promise.reject(new Error("no key"));
        return Core.encrypt(c.key, text);
      },
      decrypt(id, content) {
        const c = channels[id];
        if (!c || !c.key) return Promise.reject(new Error("no key"));
        return Core.decrypt(c.key, content);
      },
    };
  }

  // ---- icons --------------------------------------------------------------

  get lockClosed() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
      '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm3 8H9V7a3 3 0 1 1 6 0v3Zm-3 4a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
      "</svg>"
    );
  }
  get lockOpen() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
      '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5 1 1 0 0 0 2 0 3 3 0 1 1 6 0v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm0 12a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
      "</svg>"
    );
  }
  get keyIcon() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
      '<path fill="currentColor" d="M14.5 2a5.5 5.5 0 0 0-5.4 6.53L2 15.63V20a1 1 0 0 0 1 1h4.5a1 1 0 0 0 1-1v-1.5H10a1 1 0 0 0 1-1V16h1.5a1 1 0 0 0 .71-.29l1.36-1.36A5.5 5.5 0 1 0 14.5 2Zm2 5.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Z"/>' +
      "</svg>"
    );
  }
  iconForState(state) {
    if (state === "on") return this.lockClosed;
    if (state === "off") return this.lockOpen;
    return this.keyIcon;
  }
  stateLabel(state) {
    return state === "on"
      ? "End to end encrypted. Messages you send are encrypted."
      : state === "off"
      ? "e2ed is off. Messages you send are plaintext."
      : "No shared password set for this conversation yet.";
  }

  // ---- Discord module lookups ---------------------------------------------

  getModules() {
    const { Webpack } = BdApi;
    this.MessageActions = Webpack.getModule((m) => m && m.sendMessage && m.editMessage);
    this.SelectedChannelStore = Webpack.getModule((m) => m && m.getChannelId && m.getLastSelectedChannelId);
  }

  currentChannelId() {
    return this.SelectedChannelStore ? this.SelectedChannelStore.getChannelId() : null;
  }

  // ---- persistence (BdApi.Data; local to this Discord install only) -------

  loadStore() {
    return BdApi.Data.load("e2ed", "channels") || {};
  }
  saveStore(store) {
    BdApi.Data.save("e2ed", "channels", store);
  }
  persistPassword(channelId, password, armed) {
    const store = this.loadStore();
    store[channelId] = { password, armed };
    this.saveStore(store);
  }
  persistArmed(channelId, armed) {
    const store = this.loadStore();
    if (store[channelId]) {
      store[channelId].armed = armed;
      this.saveStore(store);
    }
  }
  restoreAll() {
    const store = this.loadStore();
    return Promise.all(
      Object.keys(store).map((channelId) => {
        const entry = store[channelId];
        return this.session.restore(channelId, entry.password, entry.armed);
      })
    );
  }

  // ---- lifecycle ----------------------------------------------------------

  start() {
    this.Core = this.buildCore();
    this.session = this.buildSession(this.Core);
    this.getModules();
    this.injectStyles();

    this.restoreAll().then(() => {
      this.patchSend();
      this.startObserver();
      this.uiTimer = setInterval(() => {
        this.refreshUi();
        this.sweep();
      }, 1500);
      this.refreshUi();
      this.sweep();
    });
  }

  stop() {
    if (this.unpatch) this.unpatch();
    if (this.observer) this.observer.disconnect();
    if (this.uiTimer) clearInterval(this.uiTimer);
    BdApi.DOM.removeStyle("e2ed-styles");
    const btn = document.getElementById("e2ed-lock-btn");
    if (btn) btn.remove();
    const banner = document.getElementById("e2ed-banner");
    if (banner) banner.remove();
  }

  // ---- outgoing: patch sendMessage ----------------------------------------

  patchSend() {
    if (!this.MessageActions) return;
    this.unpatch = BdApi.Patcher.instead("e2ed", this.MessageActions, "sendMessage", (self, args, original) => {
      const channelId = args[0];
      const message = args[1];
      if (
        message &&
        typeof message.content === "string" &&
        message.content.length > 0 &&
        this.session.canEncrypt(channelId) &&
        !this.Core.isEncrypted(message.content)
      ) {
        return this.session
          .encrypt(channelId, message.content)
          .then((cipher) => {
            const newMsg = Object.assign({}, message, { content: cipher });
            const newArgs = args.slice();
            newArgs[1] = newMsg;
            return original.apply(self, newArgs);
          })
          .catch(() => original.apply(self, args));
      }
      return original.apply(self, args);
    });
  }

  // ---- incoming: DOM observer ---------------------------------------------

  startObserver() {
    this.observer = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        for (const node of mut.addedNodes) {
          if (node.nodeType === 1) this.processNode(node);
        }
      }
    });
    this.observer.observe(document.body, { childList: true, subtree: true });
  }

  sweep() {
    this.processNode(document.body);
  }

  processNode(node) {
    if (!node.querySelectorAll) return;
    const els =
      node.matches && node.matches('[id^="message-content-"]')
        ? [node]
        : node.querySelectorAll('[id^="message-content-"]');
    els.forEach((el) => {
      if (el.dataset.e2edStatus === "decrypted" || el.dataset.e2edStatus === "skip") return;

      if (!el.dataset.e2edStatus) {
        const text = el.textContent || "";
        if (!this.Core.isEncrypted(text)) {
          el.dataset.e2edStatus = "skip";
          return;
        }
        el.dataset.e2edCipher = text;
        el.dataset.e2edStatus = "pending";
        el.textContent = "";
        const lock = document.createElement("span");
        lock.className = "e2ed-banner-icon";
        lock.innerHTML = this.lockClosed;
        const note = document.createElement("span");
        note.className = "e2ed-file-notice";
        note.textContent = " Encrypted message (enter the shared password to read it)";
        el.appendChild(lock);
        el.appendChild(note);
      }

      const channelId = this.currentChannelId();
      if (channelId && this.session.canDecrypt(channelId)) {
        this.session
          .decrypt(channelId, el.dataset.e2edCipher)
          .then((plain) => {
            el.textContent = plain;
            const tag = document.createElement("span");
            tag.className = "e2ed-decrypted-tag";
            tag.innerHTML = this.lockClosed + "e2ed";
            el.appendChild(tag);
            el.dataset.e2edStatus = "decrypted";
          })
          .catch(() => {
            /* still pending; will retry on next sweep */
          });
      }
    });
  }

  // ---- UI -----------------------------------------------------------------

  uiFor(channelId) {
    if (!this.uiState[channelId]) this.uiState[channelId] = { formOpen: false };
    return this.uiState[channelId];
  }

  refreshUi() {
    this.ensureLockButton();
    this.ensureBanner();
  }

  ensureLockButton() {
    // Scoped to the message compose form: a bare `[class*="buttons_"]` match
    // also matches the user panel's mute/deafen/settings toolbar, which
    // appears earlier in the DOM and crowds the lock button among those icons.
    const form = document.querySelector('form[class*="form_"]');
    const toolbar = form ? form.querySelector('[class*="buttons_"]') : null;
    if (!toolbar) return;
    let btn = document.getElementById("e2ed-lock-btn");
    if (!btn) {
      btn = document.createElement("button");
      btn.id = "e2ed-lock-btn";
      btn.className = "e2ed-lock-btn";
      btn.type = "button";
      btn.addEventListener("click", () => this.onLockClick());
      toolbar.insertBefore(btn, toolbar.firstChild);
    } else if (btn.parentNode !== toolbar) {
      toolbar.insertBefore(btn, toolbar.firstChild);
    }
    const state = this.session.getState(this.currentChannelId());
    btn.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    btn.classList.add("e2ed-" + state);
    btn.title = this.stateLabel(state);
    btn.innerHTML = this.iconForState(state);
  }

  onLockClick() {
    const channelId = this.currentChannelId();
    if (!channelId) return;
    if (!this.session.hasKey(channelId)) {
      this.uiFor(channelId).formOpen = true;
      this.refreshUi();
      this.focusPasswordInput();
      return;
    }
    const newState = this.session.toggle(channelId);
    if (newState) this.persistArmed(channelId, newState === "on");
    this.refreshUi();
  }

  focusPasswordInput() {
    const input = document.getElementById("e2ed-pw-input");
    if (input) input.focus();
  }

  onSubmitPassword(channelId) {
    const input = document.getElementById("e2ed-pw-input");
    if (!input || !input.value) return;
    const password = input.value;
    this.session.setPassword(channelId, password).then(() => {
      this.persistPassword(channelId, password, true);
      this.uiFor(channelId).formOpen = false;
      this.refreshUi();
      this.sweep();
    });
  }

  ensureBanner() {
    const channelId = this.currentChannelId();
    if (!channelId) return;
    const form = document.querySelector('form[class*="form_"]');
    if (!form) return;
    let banner = document.getElementById("e2ed-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "e2ed-banner";
      banner.className = "e2ed-banner";
      form.parentNode.insertBefore(banner, form);
    }

    const state = this.session.getState(channelId);
    const fp = this.session.getConfirmation(channelId);
    const ui = this.uiFor(channelId);

    const signature = channelId + "|" + state + "|" + fp + "|" + ui.formOpen;
    const pwHasFocus = document.activeElement && document.activeElement.id === "e2ed-pw-input";
    if (banner.dataset.e2edSig === signature && pwHasFocus) return;
    banner.dataset.e2edSig = signature;

    banner.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    banner.classList.add("e2ed-" + state);

    const actionHtml =
      state !== "no-key"
        ? ' <button type="button" class="e2ed-banner-action" id="e2ed-change-pw">Change password</button>'
        : "";
    const fpHtml = fp
      ? '<span class="e2ed-banner-fp" title="Password confirmation code">' + fp + "</span>"
      : "";

    const rowHtml =
      '<div class="e2ed-banner-row"><span class="e2ed-banner-icon">' +
      this.iconForState(state) +
      "</span><span>" +
      this.stateLabel(state) +
      " Files are not supported (text only)." +
      actionHtml +
      "</span>" +
      fpHtml +
      "</div>";

    let formHtml = "";
    if (state === "no-key" || ui.formOpen) {
      formHtml =
        '<div class="e2ed-pw-form">' +
        '<input type="password" id="e2ed-pw-input" class="e2ed-pw-input" ' +
        'placeholder="Shared password for this conversation" autocomplete="off" />' +
        '<button type="button" class="e2ed-pw-submit" id="e2ed-pw-submit">Set</button>' +
        "</div>";
    }

    banner.innerHTML = rowHtml + formHtml;

    const submitBtn = document.getElementById("e2ed-pw-submit");
    if (submitBtn) submitBtn.addEventListener("click", () => this.onSubmitPassword(channelId));
    const pwInput = document.getElementById("e2ed-pw-input");
    if (pwInput)
      pwInput.addEventListener("keydown", (evt) => {
        if (evt.key === "Enter") {
          evt.preventDefault();
          this.onSubmitPassword(channelId);
        }
      });
    const changeBtn = document.getElementById("e2ed-change-pw");
    if (changeBtn)
      changeBtn.addEventListener("click", () => {
        ui.formOpen = true;
        this.refreshUi();
        this.focusPasswordInput();
      });
  }

  // ---- styles -------------------------------------------------------------

  injectStyles() {
    BdApi.DOM.addStyle(
      "e2ed-styles",
      `
.e2ed-lock-btn{display:inline-flex;align-items:center;justify-content:center;align-self:center;flex:0 0 auto;width:44px;height:44px;margin:0 2px;padding:0;border:none;background:transparent;cursor:pointer;color:var(--interactive-normal,#b5bac1);border-radius:8px;transition:color .15s ease,background-color .15s ease;}
.e2ed-lock-btn:hover{color:var(--interactive-hover,#dbdee1);background:var(--background-modifier-hover,rgba(255,255,255,.05));}
.e2ed-lock-btn svg{width:24px;height:24px;}
.e2ed-lock-btn.e2ed-on{color:var(--green-360,#23a55a);}
.e2ed-lock-btn.e2ed-off{color:var(--red-360,#f23f43);}
.e2ed-lock-btn.e2ed-no-key{color:var(--text-muted,#949ba4);}
.e2ed-banner{display:flex;flex-direction:column;gap:6px;padding:8px 12px;margin:0 16px 8px 16px;border-radius:8px;font-size:13px;line-height:16px;background:var(--background-secondary,#2b2d31);color:var(--text-normal,#dbdee1);border-left:3px solid var(--text-muted,#949ba4);}
.e2ed-banner.e2ed-on{border-left-color:var(--green-360,#23a55a);}
.e2ed-banner.e2ed-off{border-left-color:var(--red-360,#f23f43);}
.e2ed-banner .e2ed-banner-row{display:flex;align-items:center;gap:8px;}
.e2ed-banner .e2ed-banner-icon{display:inline-flex;flex:0 0 auto;}
.e2ed-banner .e2ed-banner-icon svg{width:16px;height:16px;}
.e2ed-banner .e2ed-banner-fp{margin-left:auto;font-family:var(--font-code,Consolas,monospace);font-size:11px;opacity:.75;}
.e2ed-banner .e2ed-banner-action{color:var(--text-link,#00a8fc);cursor:pointer;background:none;border:none;padding:0;font:inherit;}
.e2ed-banner .e2ed-banner-action:hover{text-decoration:underline;}
.e2ed-pw-form{display:flex;align-items:center;gap:6px;}
.e2ed-pw-input{flex:1 1 auto;min-width:0;padding:6px 8px;border-radius:4px;border:1px solid var(--background-modifier-accent,#4e5058);background:var(--background-primary,#313338);color:var(--text-normal,#dbdee1);font-size:13px;font-family:inherit;}
.e2ed-pw-input:focus{outline:none;border-color:var(--brand-experiment,#5865f2);}
.e2ed-pw-submit{flex:0 0 auto;padding:6px 12px;border-radius:4px;border:none;cursor:pointer;background:var(--brand-experiment,#5865f2);color:#fff;font-size:13px;font-weight:500;}
.e2ed-pw-submit:hover{filter:brightness(.92);}
.e2ed-decrypted-tag{display:inline-flex;align-items:center;gap:3px;margin-left:6px;padding:0 6px;height:15px;border-radius:8px;font-size:10px;font-weight:600;text-transform:uppercase;vertical-align:middle;background:var(--green-360,#23a55a);color:#fff;}
.e2ed-decrypted-tag svg{width:10px;height:10px;}
.e2ed-file-notice{color:var(--text-muted,#949ba4);font-style:italic;}
`
    );
  }
};

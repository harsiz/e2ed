/*
 * e2ed - Vencord plugin
 *
 * Vencord build of e2ed (End to End for Discord). Drop this folder into
 * Vencord's `src/userplugins/` (so the path is `src/userplugins/e2ed/index.js`)
 * and rebuild Vencord (`pnpm build`), or use it with a dev build.
 *
 * Outgoing text is encrypted with Vencord's official pre-send hook
 * (addMessagePreSendListener), which hands us the channel id and the outgoing
 * message object before it is sent and lets us rewrite `content`. That means
 * e2ed never has to touch Discord's editor or network layer here, so there is
 * no risk of the editor corruption the raw DOM approaches ran into. When a
 * channel is not armed (lock not green) the listener returns immediately and
 * does nothing, so Discord behaves exactly as default.
 *
 * Incoming text is decrypted, and the lock toggle / status banner are drawn,
 * by observing the DOM, the same way the Chrome and BetterDiscord builds do.
 *
 * Key agreement is password based and identical to the other builds: both
 * people enter the same password (agreed out of band) for a conversation and
 * each derives the same AES-256-GCM key locally with PBKDF2. Text only; files
 * and attachments are never touched.
 */

import definePlugin from "@utils/types";
import * as MessageEvents from "@api/MessageEvents";
import { SelectedChannelStore } from "@webpack/common";

// The pre-send API was renamed from addPreSendListener to
// addMessagePreSendListener in newer Vencord; support both.
const addPreSend = MessageEvents.addMessagePreSendListener || MessageEvents.addPreSendListener;
const removePreSend = MessageEvents.removeMessagePreSendListener || MessageEvents.removePreSendListener;

// ---- crypto core (mirror of core/e2ed-core.js) --------------------------

function buildCore() {
    const subtle = crypto.subtle;
    const CIPHER_PREFIX = "e2ed:1:";
    const PBKDF2_ITERATIONS = 200000;
    const te = new TextEncoder();
    const td = new TextDecoder();

    const toBytes = s => te.encode(s);
    const fromBytes = b => td.decode(b);

    const b64url = buf => {
        const bytes = new Uint8Array(buf);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };
    const unb64url = s => {
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
                .then(keyMaterial =>
                    subtle.deriveKey(
                        {
                            name: "PBKDF2",
                            salt: toBytes("e2ed-pwd-salt-v1:" + channelId),
                            iterations: PBKDF2_ITERATIONS,
                            hash: "SHA-256"
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
            return subtle.digest("SHA-256", toBytes(channelId + "|" + normalized)).then(d => {
                const bytes = new Uint8Array(d).slice(0, 6);
                let hex = "";
                for (let i = 0; i < bytes.length; i++) {
                    const h = bytes[i].toString(16);
                    hex += (h.length === 1 ? "0" : "") + h;
                }
                return hex.match(/.{1,4}/g).join(" ");
            });
        },
        isEncrypted: c => typeof c === "string" && c.indexOf(CIPHER_PREFIX) === 0,
        encrypt: (key, text) => {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            return subtle
                .encrypt({ name: "AES-GCM", iv }, key, toBytes(text))
                .then(cb => CIPHER_PREFIX + b64url(concat(iv, new Uint8Array(cb))));
        },
        decrypt: (key, content) => {
            const packed = unb64url(content.slice(CIPHER_PREFIX.length));
            const iv = packed.slice(0, 12);
            const cipher = packed.slice(12);
            return subtle.decrypt({ name: "AES-GCM", iv }, key, cipher).then(pb => fromBytes(new Uint8Array(pb)));
        }
    };
}

// ---- session state (mirror of core/e2ed-session.js) ---------------------

function buildSession(Core) {
    const channels = {}; // channelId -> { key, armed, confirmation }
    const ch = id => {
        if (!channels[id]) channels[id] = { key: null, armed: false, confirmation: null };
        return channels[id];
    };
    const getState = id => {
        const c = channels[id];
        if (!c || !c.key) return "no-key";
        return c.armed ? "on" : "off";
    };
    return {
        hasKey: id => !!(channels[id] && channels[id].key),
        getState,
        getConfirmation: id => (channels[id] ? channels[id].confirmation : null),
        setPassword(id, password) {
            const c = ch(id);
            return Core.deriveKeyFromPassword(password, id)
                .then(key => {
                    c.key = key;
                    c.armed = true;
                    return Core.passwordFingerprint(password, id);
                })
                .then(fp => {
                    c.confirmation = fp;
                    return { state: getState(id), confirmation: fp };
                });
        },
        restore(id, password, armed) {
            const c = ch(id);
            return Core.deriveKeyFromPassword(password, id)
                .then(key => {
                    c.key = key;
                    c.armed = !!armed;
                    return Core.passwordFingerprint(password, id);
                })
                .then(fp => {
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
        isArmed: id => !!(channels[id] && channels[id].armed && channels[id].key),
        canEncrypt(id) {
            return this.isArmed(id);
        },
        canDecrypt: id => !!(channels[id] && channels[id].key),
        encrypt(id, text) {
            const c = channels[id];
            if (!c || !c.key) return Promise.reject(new Error("no key"));
            return Core.encrypt(c.key, text);
        },
        decrypt(id, content) {
            const c = channels[id];
            if (!c || !c.key) return Promise.reject(new Error("no key"));
            return Core.decrypt(c.key, content);
        }
    };
}

// ---- icons --------------------------------------------------------------

const LOCK_CLOSED =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm3 8H9V7a3 3 0 1 1 6 0v3Zm-3 4a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
    "</svg>";
const LOCK_OPEN =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M12 2a5 5 0 0 0-5 5 1 1 0 0 0 2 0 3 3 0 1 1 6 0v3H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm0 12a1.5 1.5 0 0 1 .75 2.8V19a.75.75 0 0 1-1.5 0v-2.2A1.5 1.5 0 0 1 12 14Z"/>' +
    "</svg>";
const KEY_ICON =
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path fill="currentColor" d="M14.5 2a5.5 5.5 0 0 0-5.4 6.53L2 15.63V20a1 1 0 0 0 1 1h4.5a1 1 0 0 0 1-1v-1.5H10a1 1 0 0 0 1-1V16h1.5a1 1 0 0 0 .71-.29l1.36-1.36A5.5 5.5 0 1 0 14.5 2Zm2 5.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Z"/>' +
    "</svg>";

function iconForState(state) {
    if (state === "on") return LOCK_CLOSED;
    if (state === "off") return LOCK_OPEN;
    return KEY_ICON;
}
function stateLabel(state) {
    return state === "on"
        ? "End to end encrypted. Messages you send are encrypted."
        : state === "off"
        ? "e2ed is off. Messages you send are plaintext."
        : "No shared password set for this conversation yet.";
}
function stateClass(state) {
    return "e2ed-" + state;
}

const STYLES = `
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
.e2ed-tampered-tag{display:inline-flex;align-items:center;gap:3px;margin-left:6px;padding:0 6px;height:15px;border-radius:8px;font-size:10px;font-weight:600;text-transform:uppercase;vertical-align:middle;background:var(--red-360,#f23f43);color:#fff;}
.e2ed-tampered-tag svg{width:10px;height:10px;}
.e2ed-file-notice{color:var(--text-muted,#949ba4);font-style:italic;}
`;

// ---- plugin -------------------------------------------------------------

const STORAGE_KEY = "e2ed_channels_v1";

let Core = null;
let session = null;
let observer = null;
let uiTimer = null;
let styleEl = null;
let preSendListener = null;
const uiState = {};

function currentChannelId() {
    try {
        return SelectedChannelStore.getChannelId();
    } catch (e) {
        return null;
    }
}

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
        /* ignore */
    }
}
function persistPassword(channelId, password, armed) {
    const store = loadStore();
    store[channelId] = { password, armed };
    saveStore(store);
}
function persistArmed(channelId, armed) {
    const store = loadStore();
    if (store[channelId]) {
        store[channelId].armed = armed;
        saveStore(store);
    }
}
function restoreAll() {
    const store = loadStore();
    return Promise.all(
        Object.keys(store).map(channelId => {
            const entry = store[channelId];
            return session.restore(channelId, entry.password, entry.armed);
        })
    );
}

function uiFor(channelId) {
    if (!uiState[channelId]) uiState[channelId] = { formOpen: false };
    return uiState[channelId];
}

// We record exactly what we render in data-e2ed-shown and re-evaluate whenever
// Discord replaces it (a message edit), so a stale "e2ed" badge can never
// linger on changed content. Because AES-GCM is authenticated, a present key
// that fails to decrypt means the ciphertext was edited/tampered and is flagged
// red; an edit into plain text drops the badge; a valid re-encryption shows the
// new text with the normal green badge.
function processNode(node) {
    if (!node || !node.querySelectorAll) return;
    const els =
        node.matches && node.matches('[id^="message-content-"]')
            ? [node]
            : node.querySelectorAll('[id^="message-content-"]');
    els.forEach(processContentEl);
}

function processContentEl(el) {
    const shown = el.getAttribute("data-e2ed-shown");
    const current = el.textContent || "";
    if (shown !== null && current === shown) {
        if (el.dataset.e2edStatus === "pending") attemptDecrypt(el);
        return;
    }
    handleRawContent(el, current);
}

function handleRawContent(el, raw) {
    if (!Core.isEncrypted(raw)) {
        removeOurTags(el);
        el.dataset.e2edStatus = "plain";
        el.setAttribute("data-e2ed-shown", el.textContent || "");
        return;
    }
    el.dataset.e2edCipher = raw;
    const channelId = currentChannelId();
    if (!channelId || !session.canDecrypt(channelId)) {
        showPendingPlaceholder(el);
        el.dataset.e2edStatus = "pending";
        return;
    }
    el.dataset.e2edStatus = "working";
    el.setAttribute("data-e2ed-shown", raw);
    attemptDecrypt(el);
}

function attemptDecrypt(el) {
    const channelId = currentChannelId();
    const cipher = el.dataset.e2edCipher;
    if (!channelId || !cipher || !session.canDecrypt(channelId)) return;
    el.dataset.e2edStatus = "working";
    session
        .decrypt(channelId, cipher)
        .then(plain => {
            el.textContent = plain;
            const tag = document.createElement("span");
            tag.className = "e2ed-decrypted-tag";
            tag.innerHTML = LOCK_CLOSED + "e2ed";
            el.appendChild(tag);
            el.dataset.e2edStatus = "decrypted";
            el.setAttribute("data-e2ed-shown", el.textContent || "");
        })
        .catch(() => {
            el.textContent = "";
            const note = document.createElement("span");
            note.className = "e2ed-file-notice";
            note.textContent = "Encrypted message could not be verified ";
            el.appendChild(note);
            const tag = document.createElement("span");
            tag.className = "e2ed-tampered-tag";
            tag.innerHTML = LOCK_OPEN + "e2ed";
            el.appendChild(tag);
            el.dataset.e2edStatus = "tampered";
            el.setAttribute("data-e2ed-shown", el.textContent || "");
        });
}

function removeOurTags(el) {
    el.querySelectorAll(".e2ed-decrypted-tag, .e2ed-tampered-tag").forEach(t => t.remove());
}

function showPendingPlaceholder(el) {
    el.textContent = "";
    const lock = document.createElement("span");
    lock.className = "e2ed-banner-icon";
    lock.innerHTML = LOCK_CLOSED;
    const note = document.createElement("span");
    note.className = "e2ed-file-notice";
    note.textContent = " Encrypted message (enter the shared password to read it)";
    el.appendChild(lock);
    el.appendChild(note);
    el.setAttribute("data-e2ed-shown", el.textContent || "");
}

function sweep() {
    processNode(document.body);
}

function ensureLockButton() {
    const form = document.querySelector('form[class*="form_"]');
    const toolbar = form ? form.querySelector('[class*="buttons_"]') : null;
    if (!toolbar) return;
    let btn = document.getElementById("e2ed-lock-btn");
    if (!btn) {
        btn = document.createElement("button");
        btn.id = "e2ed-lock-btn";
        btn.className = "e2ed-lock-btn";
        btn.type = "button";
        btn.addEventListener("click", onLockClick);
        toolbar.insertBefore(btn, toolbar.firstChild);
    } else if (btn.parentNode !== toolbar) {
        toolbar.insertBefore(btn, toolbar.firstChild);
    }
    const state = session.getState(currentChannelId());
    btn.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    btn.classList.add(stateClass(state));
    btn.title = stateLabel(state);
    btn.innerHTML = iconForState(state);
}

function onLockClick() {
    const channelId = currentChannelId();
    if (!channelId) return;
    if (!session.hasKey(channelId)) {
        uiFor(channelId).formOpen = true;
        refreshUi();
        focusPasswordInput();
        return;
    }
    const newState = session.toggle(channelId);
    if (newState) persistArmed(channelId, newState === "on");
    refreshUi();
}

function focusPasswordInput() {
    const input = document.getElementById("e2ed-pw-input");
    if (input) input.focus();
}

function onSubmitPassword(channelId) {
    const input = document.getElementById("e2ed-pw-input");
    if (!input || !input.value) return;
    const password = input.value;
    session.setPassword(channelId, password).then(() => {
        persistPassword(channelId, password, true);
        uiFor(channelId).formOpen = false;
        refreshUi();
        sweep();
    });
}

function ensureBanner() {
    const channelId = currentChannelId();
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

    const state = session.getState(channelId);
    const fp = session.getConfirmation(channelId);
    const ui = uiFor(channelId);

    const signature = channelId + "|" + state + "|" + fp + "|" + ui.formOpen;
    const pwHasFocus = document.activeElement && document.activeElement.id === "e2ed-pw-input";
    if (banner.dataset.e2edSig === signature && pwHasFocus) return;
    banner.dataset.e2edSig = signature;

    banner.classList.remove("e2ed-on", "e2ed-off", "e2ed-no-key");
    banner.classList.add(stateClass(state));

    const actionHtml =
        state !== "no-key"
            ? ' <button type="button" class="e2ed-banner-action" id="e2ed-change-pw">Change password</button>'
            : "";
    const fpHtml = fp
        ? '<span class="e2ed-banner-fp" title="Password confirmation code">' + fp + "</span>"
        : "";

    const rowHtml =
        '<div class="e2ed-banner-row"><span class="e2ed-banner-icon">' +
        iconForState(state) +
        "</span><span>" +
        stateLabel(state) +
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
    if (submitBtn) submitBtn.addEventListener("click", () => onSubmitPassword(channelId));
    const pwInput = document.getElementById("e2ed-pw-input");
    if (pwInput)
        pwInput.addEventListener("keydown", evt => {
            if (evt.key === "Enter") {
                evt.preventDefault();
                onSubmitPassword(channelId);
            }
        });
    const changeBtn = document.getElementById("e2ed-change-pw");
    if (changeBtn)
        changeBtn.addEventListener("click", () => {
            ui.formOpen = true;
            refreshUi();
            focusPasswordInput();
        });
}

function refreshUi() {
    ensureLockButton();
    ensureBanner();
}

export default definePlugin({
    name: "e2ed",
    description:
        "Simple end to end encryption for Discord DMs and server messages. Both parties need e2ed installed. Text only, no files.",
    authors: [{ name: "harsiz", id: 0n }],

    start() {
        Core = buildCore();
        session = buildSession(Core);

        styleEl = document.createElement("style");
        styleEl.id = "e2ed-styles";
        styleEl.textContent = STYLES;
        document.head.appendChild(styleEl);

        // Outgoing: Vencord's official pre-send hook. Returns immediately (and
        // does nothing) unless the channel is armed, so "off" is pure default.
        preSendListener = addPreSend(async (channelId, message) => {
            if (!message || typeof message.content !== "string" || message.content.length === 0) return;
            if (!session.canEncrypt(channelId)) return;
            if (Core.isEncrypted(message.content)) return;
            try {
                message.content = await session.encrypt(channelId, message.content);
            } catch (e) {
                console.warn("[e2ed] encryption failed, sending as plaintext", e);
            }
        });

        restoreAll().then(() => {
            observer = new MutationObserver(mutations => {
                for (const mut of mutations) {
                    for (const node of mut.addedNodes) {
                        if (node.nodeType === 1) processNode(node);
                    }
                }
            });
            observer.observe(document.body, { childList: true, subtree: true });

            uiTimer = setInterval(() => {
                refreshUi();
                sweep();
            }, 1500);
            refreshUi();
            sweep();
        });
    },

    stop() {
        if (preSendListener && removePreSend) removePreSend(preSendListener);
        if (observer) observer.disconnect();
        if (uiTimer) clearInterval(uiTimer);
        if (styleEl && styleEl.parentNode) styleEl.parentNode.removeChild(styleEl);
        const btn = document.getElementById("e2ed-lock-btn");
        if (btn) btn.remove();
        const banner = document.getElementById("e2ed-banner");
        if (banner) banner.remove();
    }
});

/*
 * e2ed-session.js
 * Per-channel key state on top of E2EDCore.
 *
 * A "session" is scoped to a Discord channel id (works identically for DMs and
 * server channels). Each channel has its own password derived key and its own
 * armed/disarmed toggle. Lock icon states:
 *
 *   "on"     -> green : password set and armed, outgoing text is encrypted
 *   "off"    -> red   : password set but disarmed, outgoing text is plaintext
 *   "no-key" -> grey  : no password set yet for this channel
 *
 * Decryption of incoming text only depends on the key being known, not on the
 * armed toggle, since a disarmed channel should still read messages sent while
 * it was armed (or by the other party).
 */

(function (root) {
  "use strict";

  var Core = root.E2EDCore;

  function SessionManager() {
    this.channels = {}; // channelId -> { key, armed, confirmation }
  }

  SessionManager.prototype._channel = function (channelId) {
    if (!this.channels[channelId]) {
      this.channels[channelId] = {
        key: null,
        armed: false,
        confirmation: null,
      };
    }
    return this.channels[channelId];
  };

  SessionManager.prototype.hasKey = function (channelId) {
    var ch = this.channels[channelId];
    return !!(ch && ch.key);
  };

  SessionManager.prototype.getState = function (channelId) {
    var ch = this.channels[channelId];
    if (!ch || !ch.key) {
      return "no-key";
    }
    return ch.armed ? "on" : "off";
  };

  SessionManager.prototype.getConfirmation = function (channelId) {
    var ch = this.channels[channelId];
    return ch ? ch.confirmation : null;
  };

  // Derive and store the key for a freshly entered password. Arms the channel
  // immediately, since setting a password is the explicit "turn it on" action.
  SessionManager.prototype.setPassword = function (channelId, password) {
    var self = this;
    var ch = this._channel(channelId);
    return Core.deriveKeyFromPassword(password, channelId)
      .then(function (key) {
        ch.key = key;
        ch.armed = true;
        return Core.passwordFingerprint(password, channelId);
      })
      .then(function (fp) {
        ch.confirmation = fp;
        return { state: self.getState(channelId), confirmation: fp };
      });
  };

  // Restore a previously derived channel from persisted storage without
  // resetting the armed flag the user last chose.
  SessionManager.prototype.restore = function (channelId, password, armed) {
    var self = this;
    var ch = this._channel(channelId);
    return Core.deriveKeyFromPassword(password, channelId)
      .then(function (key) {
        ch.key = key;
        ch.armed = !!armed;
        return Core.passwordFingerprint(password, channelId);
      })
      .then(function (fp) {
        ch.confirmation = fp;
        return self.getState(channelId);
      });
  };

  // Flip armed/disarmed. No-op (returns null) if no key exists yet.
  SessionManager.prototype.toggle = function (channelId) {
    var ch = this.channels[channelId];
    if (!ch || !ch.key) {
      return null;
    }
    ch.armed = !ch.armed;
    return this.getState(channelId);
  };

  SessionManager.prototype.isArmed = function (channelId) {
    var ch = this.channels[channelId];
    return !!(ch && ch.armed && ch.key);
  };

  SessionManager.prototype.canEncrypt = function (channelId) {
    return this.isArmed(channelId);
  };

  SessionManager.prototype.canDecrypt = function (channelId) {
    return this.hasKey(channelId);
  };

  SessionManager.prototype.encrypt = function (channelId, plaintext) {
    var ch = this.channels[channelId];
    if (!ch || !ch.key) {
      return root.Promise.reject(new Error("no key for channel"));
    }
    return Core.encrypt(ch.key, plaintext);
  };

  SessionManager.prototype.decrypt = function (channelId, content) {
    var ch = this.channels[channelId];
    if (!ch || !ch.key) {
      return root.Promise.reject(new Error("no key for channel"));
    }
    return Core.decrypt(ch.key, content);
  };

  SessionManager.prototype.reset = function (channelId) {
    delete this.channels[channelId];
  };

  root.E2EDSession = SessionManager;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = SessionManager;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);

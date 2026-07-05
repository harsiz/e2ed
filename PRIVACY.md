# Privacy Policy for e2ed

Last updated: 2026-07-05

e2ed is a browser extension that adds end to end encryption to Discord text messages. This policy explains what data the extension handles.

## Data collection

e2ed does not collect, transmit, or sell any user data. There are no servers operated by e2ed, no analytics, and no tracking of any kind.

## What e2ed stores, and where

- **Password**: the shared password you set for a conversation is stored only in your browser's local storage on your own device, scoped to the Discord channel it was set for. It is never transmitted anywhere by e2ed, including to the developer of e2ed.
- **Message content**: e2ed encrypts message text locally in your browser before it is sent, and decrypts it locally after it is received. e2ed does not collect, log, or transmit message content to any third party. Encrypted messages are delivered to Discord as part of your own normal use of Discord, exactly as any other message would be.

## Permissions

- **discord.com host access**: required so the extension's code can run on Discord pages to add the lock control, encrypt outgoing text, and decrypt incoming text.
- **scripting / activeTab**: used only by the "Forget All Passwords" button in the extension popup, to clear e2ed's own locally stored passwords from the active Discord tab. Not used for anything else.

## Third parties

e2ed does not share any data with third parties. It does not use analytics, advertising, or remote code of any kind; all code runs locally in your browser.

## Changes to this policy

If this policy changes, the updated version will be posted at this same location in the repository.

## Contact

Questions can be raised via the [GitHub repository](https://github.com/harsiz/e2ed) issues page.

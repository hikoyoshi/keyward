Keyward - personal password manager (portable)
==============================================

Keyward (key + steward) keeps your website logins and other passwords, and lets AI tools
log in to websites for you after you approve - without the AI ever getting the password.
Formerly called PASS_PW. Chinese instructions: README.zh-TW.txt

Getting started
---------------
1. Put this folder somewhere permanent, for example D:\Tools\Keyward, and do not move it
   afterwards (AI tools remember the full path of keyward-mcp.exe).
2. Run keyward.exe and create a master password: at least 8 characters, with an uppercase
   letter and a symbol, and not easy to guess
   (common passwords such as Password1! are refused; a meter shows the strength).
3. In Settings, export an encrypted backup and keep it on a USB stick or another drive.

The interface follows the Windows display language (English or Traditional Chinese);
change it in Settings > Language.

Upgrading from PASS_PW
----------------------
- Close passpw.exe first, then open keyward.exe. Keyward copies the old vault; the master
  password, Email codes and all items carry over. The old folder %LOCALAPPDATA%\PASS_PW is
  not deleted; remove it yourself once everything works.
- Pair your AI tools again: revoke the old connection on the AI agent page, then use
  Add AI connection > Auto setup. The old "passpw" entry is removed automatically.
- Old .passpw backup files can be restored directly.

Where your data is
------------------
- Vault: %LOCALAPPDATA%\Keyward\vault.db (encrypted), not in this program folder.
- Deleting this folder does not delete the vault. To remove everything, export a backup
  first, then delete %LOCALAPPDATA%\Keyward.
- New computer: "Export backup" on the old one, then "Restore from backup" in Keyward on
  the new one.

AI agent login
--------------
- Needs Google Chrome.
- Edit a website login and tick "Let paired AI tools ask to log in", then go to the
  AI agent page and click Add AI connection.
  If Claude Code, Codex or OpenCode is found, click "Auto setup" (the tool's config file
  is backed up first), then restart that AI tool. Other tools: use "Manual setup".
- When an AI asks to log in, Keyward shows an approval window: Deny, Allow once
  (15 minutes), or Allow this site (choose a time).
- In an emergency, click "Lock all & stop" at the top right.

Forgot the master password
--------------------------
- With Email codes turned on: on the lock screen choose "Forgot the master password?
  Reset it with an Email code"; when unlocked, use Settings > Change master password >
  "Send an Email code".
- Without Email codes: restore from a backup (you need the backup password).

Requirements: Windows 10 / 11 (WebView2 built in).
License: MIT (LICENSE.txt). Source: https://github.com/hikoyoshi/keyward

# SecureVault — coursework web demonstration

A local password-vault web app built around the included `Keychain` implementation. Features include master-password unlock/lock, add/view/update/delete logins, search, show/hide, copy, password generation and a security overview.

## Run (Windows PowerShell)

1. Extract the ZIP.
2. Open PowerShell in `SecureVault_Project`.
3. Run `npm install`.
4. Run `npm start`.
5. Open http://127.0.0.1:3000

Node.js 18 or later is recommended.

On first launch, enter a new master password to create the vault. Use the same password to unlock it later. The application does not save the master password. If it is forgotten, the vault cannot be recovered.

## Files

- `password-manager.js`: PBKDF2, HMAC indexing, AES-GCM records, fixed-size padding, encrypted domain directory, SHA-256 dump checksum and optional checksum verification on load.
- `server.js`: local Express API and vault persistence.
- `public/`: frontend.
- `data/`: created vault and checksum files.

## Cryptographic design

- PBKDF2-HMAC-SHA-256, 1,500,000 iterations, 16-byte random salt.
- HMAC-SHA-256 domain tags as KVS keys.
- AES-256-GCM encrypts each password separately.
- Domain tag is used as AES-GCM additional authenticated data to prevent swapping records between domains.
- Password plaintext is padded to a fixed 260-byte block (4-byte length plus 256-byte area).
- The domain directory and password-check marker are encrypted with AES-GCM.
- `dump()` returns JSON representation and SHA-256 checksum. `load()` verifies the checksum if supplied.

The KVS remains a JavaScript object named `kvs`. An extra encrypted `directory` field and `list()` method are included to support displaying domain names in the web UI without storing them in plaintext.

## Important limitations

This is a local coursework demonstration, not a production password manager or independently audited product. The checksum is stored in `data/vault.check` beside `data/vault.json`; this demonstrates the trusted-check API but is not genuinely trusted storage because an attacker who can change both files can replace both. A production deployment must store the checksum in a separate trusted location.

The app binds only to `127.0.0.1`. It does not provide HTTPS, multi-user access, browser extension integration, secure clipboard clearing, hardware-backed trusted storage or protection against malware running on the computer. Do not use it for real high-value credentials.

For the lecturer's programming submission, submit the required `password-manager.js` separately if the portal requests only that file. This ZIP contains the web demonstration and supporting project files.

# RDVAULT

A modern desktop client for [HashiCorp Vault](https://www.vaultproject.io/) with a built-in local mode, Chrome autofill extension, and CLI tool.

Built with Electron + React.

![CI](https://github.com/Blazefive/RDVAULT/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Vault](https://img.shields.io/badge/Vault-1.12%2B-black)

---

## Quick Start

**Download the installer** from the [Releases page](../../releases/latest) and run it. Choose between **Enterprise** (Vault server) or **Local** (offline, encrypted database) mode.

> **Note:** The installer is not code-signed yet. Windows Defender SmartScreen may show a warning. Click **More info** → **Run anyway** to proceed.

To build the installer yourself, see [Installation from source](#from-source) below.

---

## Features

### Two modes

| | Enterprise | Local |
|---|---|---|
| Backend | HashiCorp Vault server | Local encrypted SQLite database |
| Auth | LDAP (Active Directory) | Local accounts |
| Network | Requires Vault server | Fully offline |
| Use case | Teams, organizations | Personal, air-gapped |

Mode is selected at install time or via `APP_MODE` in `config.cfg`.

### Secret Management
- KV v2 engine support (versioning, soft-delete, restore)
- KV v1 compatibility
- Folder hierarchy with drag-and-drop
- Secrets: username, password, URL, notes, tags, custom fields, attachments
- SSH keys storage
- TOTP (2FA) generation and management
- Password generator with strength indicator
- Version history with restore
- Bulk select, migrate, copy, move between vaults
- Self-service: users create and manage personal vaults under `users/<username>/`

### Security
- AES-256-GCM encryption (local mode) with PBKDF2 key derivation (210k iterations, SHA-512)
- Vault token in memory only, never persisted
- Secure clipboard with auto-clear (12s)
- Session timeout (15min idle, 3h locked)
- Brute force protection with exponential backoff
- Input validation and XSS prevention
- Context isolation and CSP headers (Electron)
- All IPC handlers validated with sender check
- Timing-safe token comparison (HMAC)

### Remote Access
- RBI (Remote Browser Isolation): open URLs in secure sandboxed Chromium sessions with auto-injected credentials
- SSH, RDP, SFTP launchers (PuTTY, mstsc, FileZilla, WinSCP)
- RBI session sharing via Vault wrapping tokens

### Chrome Extension
- Autofill credentials on web pages
- Syncs with desktop app via encrypted local file
- TOTP code relay
- Manifest V3

### CLI (`mvault`)
- `mvault engines` — list available vaults
- `mvault ls <engine>` — list secrets
- `mvault get <engine>/<path> -k <field>` — retrieve a secret
- `mvault status` — check connection
- Designed for AI agents (Claude Code, scripts)
- Confirmation popup per access (configurable auto-approve per vault)
- Burst detection: forces confirmation after 15 rapid auto-approved accesses

### Admin Panel
- Policy builder (HCL)
- Engine management (create, delete, configure)
- AD group mapping
- Audit log viewer (local files or SSH)

### i18n
12 languages: English (default), French, Spanish, German, Russian, Chinese, Portuguese, Italian, Japanese, Korean, Arabic, Turkish.

Configurable via Settings UI or `LANG` in `config.cfg` for mass deployment.

### Import / Export
- Export vaults to CSV or XML
- Import from CSV or XML with duplicate handling (skip or overwrite)
- CSV formula injection protection on export

---

## Installation

### From installer

Download `RDVAULT Setup x.x.x.exe` from [Releases](../../releases). The installer lets you choose between **Enterprise** and **Local** mode.

Silent install:
```bash
"RDVAULT Setup 1.4.0.exe" /S /MODE=local
# or with config file:
"RDVAULT Setup 1.4.0.exe" /S /CONFIG=C:\path\to\config.cfg
```

### From source

```bash
git clone https://github.com/your-username/rdvault.git
cd rdvault
npm install
```

**Development:**
```bash
npm start          # React dev server (port 3000)
npm run electron   # Electron app (in another terminal)
```

**Build installer:**
```bash
npm run dist       # Build React + package Windows installer
```

---

## Configuration

### config.cfg

```ini
# Enterprise mode: Vault server URL
VAULT_URL=https://vault.example.com:8200

# LDAP auth path in Vault
LDAP_AUTH_PATH=auth/ldap

# Trusted SSL domains (comma-separated, for self-signed certs)
TRUSTED_DOMAINS=vault.example.com,localhost,127.0.0.1

# RBI proxy URL (optional, for secure session sharing)
RBI_PROXY_URL=

# App mode: enterprise or local
APP_MODE=enterprise

# Default language (en, fr, es, de, ru, zh, pt, it, ja, ko, ar, tr)
LANG=en
```

Place this file next to the executable for deployment, or in `%APPDATA%/rdvault/` for per-user config.

---

## CLI Tool

The `mvault` CLI lets you access secrets from a terminal or scripts. Requires the desktop app to be running.

### Install

```bash
cd cli
npm link
```

### Usage

```bash
mvault status                                # Check connection
mvault engines                               # List vaults
mvault ls users/me/my-vault                  # List secrets
mvault get users/me/my-vault/server -k password  # Get a field
mvault rules                                 # Show auto-approve rules
```

### SSH with mvault

```bash
# Get host key (once per server)
ssh-keyscan -t ed25519 10.0.0.5
ssh-keygen -lf <(echo "10.0.0.5 ssh-ed25519 AAAA...")

# Connect using vault credentials
plink -batch -hostkey "SHA256:..." -ssh \
  -pw "$(mvault get engine/server -k password)" \
  admin@10.0.0.5 "hostname && uptime"
```

See [`cli/README.md`](cli/README.md) for full documentation.

---

## Server Deployment (Enterprise Mode)

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for a complete guide to set up the Vault server from scratch, including:

- Vault installation and configuration
- TLS certificates
- LDAP authentication setup
- Policy templates (admin, moderator, RW, RO, self-service)
- AD group mapping
- RBI proxy setup
- Firewall rules
- Backup procedures

---

## Architecture

```
VAULT/
├── electron/                  # Electron main process
│   ├── main.js                # Window management, IPC handlers, sync server
│   ├── preload.js             # Context bridge (8 API namespaces)
│   ├── secureSession.js       # RBI: Puppeteer credential injection
│   ├── configLoader.js        # Multi-source config loading
│   ├── secureClipboard.js     # Clipboard with auto-clear
│   ├── cliServer.js           # CLI HTTP server
│   └── localVault/            # Local mode backend
│       ├── localVaultServer.js    # HTTP server mimicking Vault API
│       ├── database.js            # SQLite init and migrations
│       ├── authService.js         # Local user management
│       ├── secretsService.js      # Engine and secret CRUD
│       ├── totpService.js         # TOTP key storage + code generation
│       └── crypto.js              # AES-256-GCM + PBKDF2
├── src/                       # React application
│   ├── App.jsx                # Main app (~6000 lines)
│   ├── AdminPanel.jsx         # Admin: policies, engines, audit
│   ├── EditSecretModal.jsx    # Create/edit secrets
│   ├── SettingsModal.jsx      # Settings: theme, columns, CLI, language, export
│   ├── i18n.js                # Internationalization system
│   ├── locales/               # 12 language files (en, fr, es, de, ru, zh, pt, it, ja, ko, ar, tr)
│   └── ...                    # Other modals and components
├── cli/                       # CLI tool (mvault)
│   ├── mvault.js              # CLI entry point
│   └── package.json
├── chrome-extension/          # Chrome autofill extension (MV3)
├── assets/                    # Icons, installer scripts
├── config.default.json        # Default configuration
├── DEPLOYMENT.md              # Server deployment guide
└── electron-builder.json      # Installer config (NSIS)
```

### How it works

**Enterprise mode:**
```
React (App.jsx) → axios → HashiCorp Vault API (HTTPS)
```

**Local mode:**
```
React (App.jsx) → axios → localVaultServer.js (HTTP, localhost)
                                    ↓
                           SQLite (AES-256-GCM encrypted)
```

The local server implements the same REST API as Vault, so React works unchanged in both modes.

**CLI flow:**
```
mvault (CLI) → HTTP → cliServer.js → IPC → React → Vault API → response → stdout
```

**Chrome extension flow:**
```
Extension → HTTP (port 45678) → sync server → encrypted file ← React
```

---

## Security Model

| Layer | Protection |
|-------|-----------|
| Electron | contextIsolation, no nodeIntegration, CSP headers, IPC sender validation |
| Network | TLS 1.2+, certificate pinning by domain whitelist |
| Authentication | LDAP (enterprise) / bcrypt (local), brute force protection, session timeout |
| Secrets at rest | Vault (enterprise) / AES-256-GCM per-field with PBKDF2-derived key (local) |
| Secrets in memory | Token in React state only, derived key in Map (never raw password), cleared on logout |
| Clipboard | Auto-clear after 12s, clipboard history wipe on Windows |
| CLI | Per-request confirmation popup, burst detection, hashed audit log, token revoked on logout |
| Export | File permissions 0o600, CSV formula injection protection |

---

## Tech Stack

- **Frontend**: React 18 (functional components, hooks)
- **Desktop**: Electron 38
- **Database** (local mode): better-sqlite3
- **Crypto**: Node.js crypto (AES-256-GCM, PBKDF2, HMAC)
- **HTTP**: Axios
- **SSH**: ssh2
- **Browser automation**: Puppeteer-core
- **Build**: react-scripts + electron-builder (NSIS)
- **i18n**: Custom React context + JSON locale files

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with `npm start` + `npm run electron`
5. Submit a pull request

---

## License

MIT

---

## Author

**Blazefive**

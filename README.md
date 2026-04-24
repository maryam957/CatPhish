# CatPhish — Phishing & Malicious-JS Protection Extension

**Security Engineering Project** — Group members: Maryam Zafar (23i-2026), Noor Amir (23i-2085), Aabish Noor Khattak (23i-2109)

---

## Quick start — Chrome extension (works offline, no backend needed)

1. Open Chrome and go to `chrome://extensions`
2. Turn on **Developer mode** (toggle, top-right)
3. Click **"Load unpacked"**
4. Select the **`extension/`** folder inside this project
5. The CatPhish icon appears in the toolbar — pin it for easy access

That's it. The extension works immediately using local heuristics and the seeded demo threat entries. The backend is only needed to pull live feed updates and receive community reports.

---

## What the extension does

| Feature | Where implemented |
|---|---|
| Real-time URL risk scoring (entropy, homoglyphs, IP literals, hyphens, patterns) | `background/url_engine.js` |
| Privacy-preserving SHA-256 hash-prefix lookup (K-anonymity) | `background/url_hasher.js` |
| Threat-feed check (Google Safe Browsing / PhishTank / OpenPhish style) | `background/threat_intel.js` |
| Malicious JS detection (keyloggers, skimmers, miners, obfuscation) | `background/malicious_js_detector.js` |
| HMAC-chained tamper-evident audit log | `background/audit_log.js` |
| Signed community phishing reports | `background/reporting.js` |
| DOM snapshot analysis (login forms, hidden iframes, script sinks) | `content/dom_analyzer.js` |
| Warning banner (closed Shadow DOM, immune to page CSS/JS) | `content/warning_banner.js` |
| Hard-block page for DANGEROUS verdicts | `block/block.html` |
| Visual risk-score dashboard popup | `popup/` |
| Settings + audit log viewer | `options/` |
| AES-256-GCM encrypted local storage | `storage/storage_manager.js` |

### Popup dashboard
Click the CatPhish toolbar icon on any page to see:
- **Risk score meter** (0–100%, colour-coded green/amber/red)
- Verdict label (SAFE / LOW RISK / SUSPICIOUS / DANGEROUS)
- Login forms, hidden iframes, suspicious scripts counts
- Detailed risk factors list with severity
- Malicious-JS signature hits (keylogger, skimmer, miner, obfuscation)
- **"Report this site as phishing"** button (sends a signed, anonymous report)

### Settings page
Right-click the toolbar icon → Options, or click the ⚙ gear in the popup:
- Toggle each threat feed (Google Safe Browsing, PhishTank, OpenPhish)
- Adjust warning and block thresholds
- Toggle warning banner injection
- View the HMAC-chained audit log and verify chain integrity
- Wipe all stored data

---

## How the security features work (for the marker)

### Privacy-preserving URL checking (K-anonymity)
```
Full URL  →  SHA-256  →  first 16 hex chars (prefix)  →  only this prefix leaves the browser
```
The backend (and threat feeds) never see the full URL. On a prefix collision, the backend returns all full hashes that share that prefix; the browser checks the actual URL hash locally. This is identical to the Google Safe Browsing v4 Update API design.

### HMAC-chained audit log
Each log entry stores:
```
{ seq, ts, prevHmac, event, hmac }
              ↑                   ↑
         link to previous    HMAC over this entry
         entry's HMAC        (using a non-extractable WebCrypto key)
```
Modifying or deleting any entry invalidates every subsequent HMAC. The options page has a "Load log" button that runs `verifyChain()` and shows ✔ Chain intact or ✗ CHAIN BROKEN.

### Community reporting with signed submissions
Reports include: `hashPrefix + category + notes + nonce + timestamp + sessionId`, all signed with an HMAC key stored as a non-extractable `CryptoKey`. The nonce + timestamp window prevents replay attacks.

### Malicious JS detection
The `MaliciousJSDetector` runs 14 regex signatures over script bodies extracted by the content script, covering:
- **Keyloggers**: `addEventListener('keydown' …) + fetch(` patterns
- **Card skimmers**: credit-card field selectors + exfiltration
- **Crypto miners**: CoinHive/CryptoLoot names, stratum+tcp://, WASM miner patterns
- **Obfuscation**: `eval(atob(…))`, hex-packed arrays, `fromCharCode` sprays
- **Dangerous sinks**: `eval()`, `document.write()`, `new Function()`
- Plus Shannon entropy check for packed blobs

---

## Backend (optional — for live feed + report sync)

### Requirements
- Node.js 18+

### Install
```bash
npm install
```

### Configure
```bash
# Generate secrets (do this once, save them somewhere safe)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Run it 3 times, use the outputs for the 3 vars below

export CATPHISH_JWT_SECRET=<32+ hex chars>
export CATPHISH_AUDIT_KEY=<64 hex chars>
export CATPHISH_REPORT_SECRET=<32+ hex chars>
export PORT=3000
```

### Run
```bash
npm start
# Backend listens at http://127.0.0.1:3000
```

### API endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | — | Server health check |
| POST | `/api/auth/register` | — | Register user |
| POST | `/api/auth/login` | — | Login, get JWT |
| POST | `/api/auth/refresh` | cookie | Rotate refresh token |
| POST | `/api/auth/logout` | Bearer | Logout |
| GET | `/api/threat-intel/updates?since=` | — | Hash-prefix feed |
| POST | `/api/threat-intel/entries` | admin JWT | Add threat hash |
| GET | `/api/threat-intel/audit` | admin JWT | Verify audit chain |
| POST | `/api/reports` | rate-limit | Submit phishing report |
| GET | `/api/reports/admin` | admin JWT | Read all reports |

---

## Project structure
```
CatPhish/
├── extension/              ← Load this folder into Chrome
│   ├── manifest.json
│   ├── background/
│   │   ├── service_worker.js       ← Main entry (wires everything)
│   │   ├── url_engine.js           ← Heuristic URL analyser (original)
│   │   ├── url_hasher.js           ← SHA-256 K-anonymity (original)
│   │   ├── threat_intel.js         ← Feed lookup (NEW)
│   │   ├── malicious_js_detector.js← JS signatures (NEW)
│   │   ├── audit_log.js            ← HMAC chain (NEW)
│   │   ├── reporting.js            ← Signed reports (NEW)
│   │   └── badge_manager.js        ← Toolbar icon (NEW)
│   ├── content/
│   │   ├── dom_analyzer.js         ← DOM snapshot (original)
│   │   ├── content_script.js       ← Enhanced (sends richer script data)
│   │   └── warning_banner.js       ← Shadow-DOM banner (NEW)
│   ├── popup/                      ← Risk dashboard (NEW UI)
│   ├── options/                    ← Settings + audit log viewer (NEW)
│   ├── block/                      ← Hard-block interstitial (NEW)
│   ├── safe-preview/               ← Sandboxed preview (original)
│   ├── storage/                    ← AES-256-GCM utils (original)
│   └── icons/
├── backend/
│   ├── server.js                   ← Express entry point (NEW)
│   ├── auth/                       ← Auth layer (original + fixed crypto)
│   ├── middleware/                 ← JWT + rate-limit middleware (original)
│   ├── controllers/                ← Reporting + threat intel (NEW)
│   ├── routes/                     ← Route wiring (NEW)
│   └── storage/                    ← Repos + server audit log (NEW)
└── package.json
```

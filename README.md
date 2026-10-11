# SecureTransfer

For cloud deployment setup, see [DEPLOYMENT.md](DEPLOYMENT.md).

Local transfer of sensitive text, image evidence, and voice transcripts. Traffic stays on the LAN. Payloads use X25519 + HKDF session keys and AES-256-GCM. Pairing is QR + public-key fingerprint. Audit logs are hash-chained.

Two physical devices use the **same** backend and the **same** web UI. Each signed-in user has a distinct X25519 identity. Neither client is permanently a sender or receiver.

## Ports (this folder)

| Service | Bind | URL |
| --- | --- | --- |
| FastAPI | `0.0.0.0:8000` | `http://<LAN-IP>:8000` |
| Vite UI | `0.0.0.0:5173` | `http://<LAN-IP>:5173` |

The Vite dev server proxies API routes to `127.0.0.1:8000`, so other laptops only need the UI origin.

## Setup

Use the same Python version that creates the venv. Do not mix 3.14 wheels into a 3.13 venv.

```bash
cd SentinelDrop-Fresh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cd frontend && npm install
```

macOS/Linux PowerShell equivalent on Windows:

```powershell
cd SentinelDrop-Fresh
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd frontend
npm install
```

Voice notes use the small English Vosk model. The backend downloads it from the
official Vosk model host on first use and caches it under
`SENTINEL_DATA_DIR/models/vosk/` (or `models/vosk/` when the data directory is
not configured). The first voice transcription needs outbound internet access
and downloads about 40 MB; later requests reuse the cached model. On Render the
configured persistent disk keeps the model across deploys. If the backend has no
outbound access, manually download `vosk-model-small-en-us-0.15` from
[Alpha Cephei Vosk models](https://alphacephei.com/vosk/models) and extract it
to that cache directory.

## Run on one laptop (also used as the LAN host)

Terminal 1 — API (reachable on the LAN):

```bash
cd SentinelDrop-Fresh
source .venv/bin/activate
export SENTINEL_RATE_LIMIT_DISABLED=1   # optional, for demos
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Terminal 2 — UI:

```bash
cd SentinelDrop-Fresh/frontend
npm run dev
```

Find this laptop's LAN IP:

```bash
ipconfig getifaddr en0    # macOS Wi-Fi
hostname -I               # Linux
ipconfig                  # Windows, look for IPv4
```

## Two physical devices (same Wi-Fi / hotspot)

1. Connect both laptops to the same Wi-Fi, LAN, or phone hotspot.
2. Start the backend and UI on **Laptop 1** as above (`--host 0.0.0.0`).
3. On Laptop 1 open `http://<LAPTOP1-IP>:5173` (or `http://127.0.0.1:5173`).
4. On Laptop 2 open `http://<LAPTOP1-IP>:5173`.
5. Register or login as **different users** on each laptop. Tokens stay in that browser only.
6. Pair (both directions), then send from either side.

### Pairing

1. On device 1, leave **This device** QR / payload visible.
2. On device 2, paste that payload (or use **Scan QR with camera** if the browser allows it), verify the fingerprint, then **Confirm and trust this device**.
3. Reverse the process so device 1 also trusts device 2.
4. Either device can then send text, images, or audio transcripts. Incoming items appear in the same UI (polling).

Camera and microphone on a **second laptop** often require a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). `http://127.0.0.1` is treated as secure; `http://192.168.x.x` usually is not. Pairing still works by pasting the payload. For camera/mic on the second device, the smallest option is local HTTPS (for example [mkcert](https://github.com/FiloSottile/mkcert) certificates) without turning off browser security. Do not use a public URL unless you need one.

### Two browser tabs on one machine

Open two tabs at `http://127.0.0.1:5173`, log in as two users, pair both ways, and transfer. This is the original two-tab workflow against a single backend.

## Security audit log

While signed in, the dashboard lists recent hash-chained events. Or:

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/audit/events
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/audit/verify
```

`/audit/verify` returns whether the chain is intact. Changing an `audit_logs` row in SQLite makes verification fail.

## Encryption demonstration log

Disabled by default. Enable only on the host running the API:

```bash
export ENABLE_ENCRYPTION_DEMO_LOG=true
export ENCRYPTION_DEMO_INCLUDE_PLAINTEXT=true   # optional; text/transcripts only
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Writes `logs/encryption_demo.log`. Image transfers log metadata and SHA-256 of ciphertext, not pixels. Session keys, passwords, and tokens are never written. `logs/` is gitignored.

## Tests

```bash
cd SentinelDrop-Fresh
source .venv/bin/activate
export SENTINEL_RATE_LIMIT_DISABLED=1
python -m pytest tests -q
```

## Security controls implemented

- bcrypt password hashing; hashed bearer tokens; logout revocation
- Per-user QR pairing payload + fingerprint confirmation
- Authenticated X25519 session establishment gated on trusted devices
- AES-256-GCM for text, files, and voice transcripts; per-direction sequence/nonce replay rejection
- Hash-chained audit log with `/audit/verify`
- Per-IP rate limiting (login is stricter)
- Sentinel Monitor application events + optional PyShark script
- Image encryption metrics: entropy, NPCR, UACI, correlation, PSNR, MSE

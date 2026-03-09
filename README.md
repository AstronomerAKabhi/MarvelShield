# 🛡️ MarvelShield

**AI-Powered, Self-Healing Web Application Firewall**

MarvelShield is a real-time security system that uses Google Gemini AI to detect, analyze, and autonomously patch web application attacks — all without human intervention. When an attack lands, the AI classifies it, generates a regex patch, deploys it to the WAF gateway, and blocks all future similar requests within seconds.

---

## 🏗️ Architecture

```
Browser / Attacker
        ↓
  gateway.py :8000  ← WAF reverse proxy (rate limiting, IP bans, regex patches)
        ↓
    app.js :8080    ← Intentionally vulnerable target (command injection demo)
        ↓
  loader.py + sensor.c ← eBPF kernel sensor (captures execve() syscalls)
        ↓
    brain.py        ← AI engine (polls Redis, calls Gemini, deploys patches)
        ↓
    bridge.js :3000 ← WebSocket relay (broadcasts events to dashboard)
        ↓
  dashboard.html    ← Live threat visualization UI
        ↓
  extension/        ← Chrome extension (client-side patch sync + user warnings)
```

| Component | File | Role |
|-----------|------|------|
| **WAF Gateway** | `gateway.py` | HTTP reverse proxy — intercepts requests, enforces patches & IP bans, exports rules |
| **Vulnerable Target** | `app.js` | Demo attack surface with intentional command injection endpoint |
| **AI Brain** | `brain.py` | Polls Redis for attack traces, queries Gemini API, generates and deploys regex patches |
| **WebSocket Bridge** | `bridge.js` | Subscribes to Redis events and streams them to the live dashboard via Socket.io |
| **Dashboard** | `dashboard.html` | Real-time threat timeline, active patches, and statistics |
| **Kernel Sensor** | `sensor.c` + `loader.py` | eBPF hook on `execve()` to correlate kernel-level command execution with HTTP requests |
| **Attack Simulator** | `simulate_attack.py` | Fires 4 attack classes to demonstrate AI response |
| **Juice Shop Demo** | `juice_attack.py` + `juice_setup.sh` | Real-world OWASP Juice Shop attack simulation |
| **Browser Extension** | `extension/` | Syncs active patches, intercepts outgoing requests, warns users on match |

---

## ✨ Features

- 🤖 **Gemini AI Analysis** — classifies attacks and generates regex patch rules automatically
- ⚡ **Sub-second Patching** — typical Time-to-Neutralize (TTN) under 1 second
- 🔒 **Auto IP Banning** — bans source IPs after 3 malicious requests
- 📊 **Live Dashboard** — real-time threat timeline at `http://localhost:3000`
- 🧠 **Kernel-Level Tracing** — eBPF captures `execve()` calls for deep attack correlation
- 🌐 **Chrome Extension** — browser-side defense with user warning modals
- 🛠️ **WAF Rule Export** — convert AI patches to Nginx / ModSecurity rules
- 🔄 **Fallback Rules** — deterministic ruleset if Gemini quota is exhausted

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- Redis (running on `127.0.0.1:6379`)
- tmux
- A [Gemini API key](https://aistudio.google.com/apikey)

### One-Command Launch

```bash
export GEMINI_API_KEY=your_api_key_here
./start.sh
```

This starts all 5 services in a tmux session, opens the dashboard, and auto-runs the attack simulation.

### Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt
npm install

# Terminal 1 — WAF Gateway
uvicorn gateway:app --host 0.0.0.0 --port 8000

# Terminal 2 — Vulnerable Target
node app.js

# Terminal 3 — AI Brain
export GEMINI_API_KEY=your_api_key_here
python3 brain.py

# Terminal 4 — Dashboard Bridge
node bridge.js

# Terminal 5 — Run Attack Simulation
python3 simulate_attack.py
```

Open `dashboard.html` in your browser or visit `http://localhost:3000`.

### OWASP Juice Shop Demo (Optional)

```bash
bash juice_setup.sh      # Installs Juice Shop on port 3001
python3 juice_attack.py  # Fires real-world OWASP attack payloads
```

### Stop All Services

```bash
./stop.sh
```

---

## ⚙️ Configuration

Create a `.env` file in the project root (or export environment variables):

```env
GEMINI_API_KEY=your_api_key_here
TARGET_APP=http://127.0.0.1:8080
DASHBOARD_USER=admin
DASHBOARD_PASS=marvelshield
```

---

## 🌐 Services & Ports

| Service | Port | Key Endpoints |
|---------|------|---------------|
| WAF Gateway | `8000` | `POST /api/execute`, `GET /api/patches`, `GET /api/stats` |
| Vulnerable Target | `8080` | `POST /api/execute`, `GET /health` |
| Dashboard + WebSocket | `3000` | `GET /`, `POST /api/login`, `/socket.io` |
| Redis | `6379` | Internal state store |
| Juice Shop (optional) | `3001` | All OWASP Juice Shop endpoints |

---

## 🎯 Attack Vectors Simulated

**`simulate_attack.py`** (4 vectors against `gateway.py`):

| Attack | Payload |
|--------|---------|
| Command Injection | `{"cmd": "ls; cat /etc/passwd"}` |
| SSRF | `{"url": "http://169.254.169.254/metadata"}` |
| Path Traversal | `GET /api/execute/../../../../etc/passwd` |
| SQL Injection | `{"id": "1; DROP TABLE users--"}` |

**`juice_attack.py`** (5 OWASP Juice Shop vectors):
- SQL Injection Login Bypass
- XSS via Search Field
- Path Traversal on FTP Directory
- SQL Injection in Product Search
- Sensitive Data Exposure via Admin Endpoint

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| AI / LLM | Google Gemini 2.5 Flash |
| WAF / Proxy | FastAPI + Uvicorn |
| Message Bus | Redis |
| Backend | Node.js + Express |
| Real-time UI | Socket.io |
| Kernel Tracing | eBPF (`sensor.c`) |
| Browser Extension | Chrome Manifest v3 |
| Session Manager | tmux |

---

## 📁 Project Structure

```
MarvelShield/
├── gateway.py          # WAF reverse proxy
├── brain.py            # AI analysis & patching engine
├── app.js              # Vulnerable demo target
├── bridge.js           # WebSocket relay server
├── dashboard.html      # Live threat dashboard
├── sensor.c            # eBPF kernel sensor
├── loader.py           # eBPF loader & event relay
├── simulate_attack.py  # Multi-vector attack simulator
├── juice_attack.py     # OWASP Juice Shop simulator
├── juice_setup.sh      # Juice Shop installer
├── start.sh            # One-click launcher
├── stop.sh             # Cleanup script
├── extension/          # Chrome browser extension
├── requirements.txt    # Python dependencies
└── package.json        # Node.js dependencies
```

---

## 🔑 How It Works

1. **Attack lands** at `gateway.py` (port 8000)
2. Gateway **logs the trace** to Redis (`trace:<UUID>` hash)
3. **`brain.py`** picks up the trace and calls the **Gemini API**
4. Gemini returns an **attack classification + regex patch**
5. Patch is stored in Redis `active_patches` and applied immediately
6. Gateway **blocks all future matching requests** with HTTP 403
7. Event is published to Redis `security_events` channel
8. **`bridge.js`** relays the event to the **live dashboard** via Socket.io
9. The **Chrome extension** syncs the new patch and warns users if their browser sends a matching request

---

## ⚠️ Disclaimer

MarvelShield is a **security research and demonstration project**. The intentionally vulnerable target (`app.js`) is designed for controlled testing only. Do not expose it to the public internet.

---

## 📄 License

MIT

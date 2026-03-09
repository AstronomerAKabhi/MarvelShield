/**
 * bridge.js — MarvelShield Security Event Bridge
 *
 * Subscribes to the Redis channel 'security_events' and re-emits every
 * message to all connected Socket.io frontend clients in real time.
 * Also persists every event to the 'threat_timeline' Redis list so new
 * clients receive full attack history on connect.
 *
 * Architecture:
 *   brain.py / gateway.py
 *       │  PUBLISH security_events <json>
 *       ▼
 *     Redis
 *       │  SUBSCRIBE security_events
 *       ▼
 *    bridge.js  (this file)
 *       │  LPUSH  threat_timeline   ← persists every event
 *       │  emit('security_event', payload)
 *       │  emit('timeline_history', […]) on new connection
 *       ▼
 *   Browser clients via Socket.io
 */

"use strict";

require("dotenv").config();

const http      = require("http");
const path      = require("path");
const crypto    = require("crypto");
const express   = require("express");
const { Server } = require("socket.io");
const Redis     = require("ioredis");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const BRIDGE_PORT     = 3000;
const REDIS_HOST      = "127.0.0.1";
const REDIS_PORT      = 6379;
const CHANNEL         = "security_events";
const SOCKET_EVENT    = "security_event";
const TIMELINE_KEY    = "threat_timeline";
const TIMELINE_MAX    = 500;   // events retained in Redis
const HISTORY_SEND    = 200;   // events sent to a newly-connected client

// Auth credentials — set in .env, fallback to safe defaults
const DASHBOARD_USER  = process.env.DASHBOARD_USER || "admin";
const DASHBOARD_PASS  = process.env.DASHBOARD_PASS || "marvelshield";
const SESSION_TTL_MS  = 24 * 60 * 60 * 1000; // 24 hours

// ---------------------------------------------------------------------------
// Session store  (token → expiry timestamp)
// ---------------------------------------------------------------------------
const sessions = new Map();

function createSession() {
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, Date.now() + SESSION_TTL_MS);
    return token;
}

function validateSession(token) {
    if (!token) return false;
    const expiry = sessions.get(token);
    if (!expiry) return false;
    if (Date.now() > expiry) { sessions.delete(token); return false; }
    return true;
}

// Purge expired sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [tok, exp] of sessions) if (now > exp) sessions.delete(tok);
}, 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// HTTP + Socket.io server
// ---------------------------------------------------------------------------
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
    cors: {
        origin:      "*",
        methods:     ["GET", "POST"],
        credentials: false,
    },
    allowEIO3:    true,           // accept older engine.io clients
    pingTimeout:  60000,
    pingInterval: 25000,
    transports:   ["polling", "websocket"],  // polling first — more reliable in WSL2
});

app.get("/health", (_req, res) => res.json({ status: "ok", bridge: "running" }));

// ── Auth endpoints ──────────────────────────────────────────────────────────
app.post("/api/signup", express.json(), async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password)
        return res.status(400).json({ success: false, error: "Username and password are required." });
    if (username.length < 3)
        return res.status(400).json({ success: false, error: "Username must be at least 3 characters." });
    if (password.length < 6)
        return res.status(400).json({ success: false, error: "Password must be at least 6 characters." });
    try {
        const existing = await store.hget("ms:credentials", "username");
        if (existing)
            return res.status(409).json({ success: false, error: "An account already exists. Please log in." });
        const hash = crypto.createHash("sha256").update(password).digest("hex");
        await store.hset("ms:credentials", "username", username, "password_hash", hash);
        console.log(`[bridge] New admin account registered: '${username}'`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Storage error: " + err.message });
    }
});

app.post("/api/login", express.json(), async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password)
        return res.status(400).json({ success: false, error: "Username and password are required." });

    let valid = false;
    try {
        // Check Redis-registered credentials first (signup takes priority over .env)
        const storedUser = await store.hget("ms:credentials", "username");
        const storedHash = await store.hget("ms:credentials", "password_hash");
        if (storedUser && storedHash) {
            const hash = crypto.createHash("sha256").update(password).digest("hex");
            valid = username === storedUser && hash === storedHash;
        } else {
            // Fall back to .env credentials
            valid = username === DASHBOARD_USER && password === DASHBOARD_PASS;
        }
    } catch {
        valid = username === DASHBOARD_USER && password === DASHBOARD_PASS;
    }

    if (valid) {
        const token = createSession();
        console.log(`[bridge] Login success for '${username}'`);
        return res.json({ success: true, token });
    }
    console.warn(`[bridge] Failed login attempt for '${username || "(none)"}'`);
    return res.status(401).json({ success: false, error: "Invalid username or password." });
});

app.post("/api/logout", express.json(), (req, res) => {
    const token = req.headers["x-auth-token"] || req.body?.token;
    if (token) sessions.delete(token);
    res.json({ success: true });
});

app.get("/api/auth/check", (req, res) => {
    const token = req.headers["x-auth-token"] || req.query.token;
    res.json({ valid: validateSession(token) });
});

// Serve the dashboard — pass token via query param from extension
// e.g. http://localhost:3000/?token=abc → validated → dashboard loads
app.get("/", (req, res) => {
    const token = req.query.token;
    // If token present and valid, serve dashboard (will auto-login via token)
    // If no token, serve dashboard (login overlay will handle it)
    res.sendFile(path.join(__dirname, "dashboard.html"));
});

io.on("connection", async (socket) => {
    console.log(`[bridge] Client connected    id=${socket.id}`);

    // Replay stored event history so the dashboard is populated immediately
    // even if brain.py fired events before the browser opened.
    try {
        const items = await store.lrange(TIMELINE_KEY, 0, HISTORY_SEND - 1);
        if (items.length > 0) {
            const history = items
                .reverse()   // list is newest-first; reverse for chronological order
                .map(raw => { try { return JSON.parse(raw); } catch { return null; } })
                .filter(Boolean);
            socket.emit("timeline_history", history);
            console.log(`[bridge] Sent ${history.length} history events to ${socket.id}`);
        }
    } catch (err) {
        console.error(`[bridge] Failed to send timeline history: ${err.message}`);
    }

    socket.on("disconnect", () => {
        console.log(`[bridge] Client disconnected id=${socket.id}`);
    });
});

// ---------------------------------------------------------------------------
// Redis clients
// A subscriber connection cannot run regular commands (LPUSH / LRANGE),
// so we maintain a second 'store' client for those operations.
// ---------------------------------------------------------------------------
const subscriber = new Redis({ host: REDIS_HOST, port: REDIS_PORT });
const store      = new Redis({ host: REDIS_HOST, port: REDIS_PORT });

subscriber.on("connect", () => {
    console.log(`[bridge] Redis subscriber connected (${REDIS_HOST}:${REDIS_PORT})`);
});
subscriber.on("error", (err) => {
    console.error(`[bridge] Redis subscriber error: ${err.message}`);
});

store.on("connect", () => {
    console.log(`[bridge] Redis store connected (${REDIS_HOST}:${REDIS_PORT})`);
});
store.on("error", (err) => {
    console.error(`[bridge] Redis store error: ${err.message}`);
});

subscriber.subscribe(CHANNEL, (err, count) => {
    if (err) {
        console.error(`[bridge] Failed to subscribe to '${CHANNEL}': ${err.message}`);
        return;
    }
    console.log(`[bridge] Subscribed to ${count} channel(s) — listening on '${CHANNEL}'`);
});

subscriber.on("message", async (channel, raw) => {
    if (channel !== CHANNEL) return;

    // Persist to the threat timeline so history survives page refreshes
    try {
        await store.lpush(TIMELINE_KEY, raw);
        await store.ltrim(TIMELINE_KEY, 0, TIMELINE_MAX - 1);
    } catch (err) {
        console.error(`[bridge] Timeline persist error: ${err.message}`);
    }

    let payload;
    try {
        payload = JSON.parse(raw);
    } catch {
        // Forward non-JSON messages as a plain string so the frontend always
        // receives a consistent object shape.
        payload = { raw };
    }

    console.log(`[bridge] Event received → broadcasting to ${io.engine.clientsCount} client(s)`);
    io.emit(SOCKET_EVENT, payload);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
server.listen(BRIDGE_PORT, "0.0.0.0", () => {
    console.log(`[bridge] Socket.io bridge listening on http://localhost:${BRIDGE_PORT}`);
    console.log(`[bridge] Waiting for messages on Redis channel '${CHANNEL}'…`);
});

// Graceful shutdown on Ctrl+C
process.on("SIGINT", async () => {
    console.log("\n[bridge] Shutting down gracefully…");
    await Promise.allSettled([subscriber.quit(), store.quit()]);
    server.close(() => process.exit(0));
});


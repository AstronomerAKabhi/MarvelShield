/**
 * ⚠️  INTENTIONALLY VULNERABLE — SECURITY DEMO ONLY
 *
 * This server is the ATTACK TARGET for the MarvelShield demo.
 * It deliberately exposes a command-injection endpoint so that
 * gateway.py + brain.py can detect, analyse, and self-heal against it.
 *
 * DO NOT deploy this in any environment accessible from the internet.
 */

const express = require("express");
const { exec }  = require("child_process");

const app  = express();
const PORT = 8080;

app.use(express.json());

// ── Intentionally vulnerable endpoint ────────────────────────────────────────
// Takes a 'cmd' field from the JSON body and executes it directly in a shell.
// This is the classic unsanitised child_process.exec() command injection sink.
app.post("/api/execute", (req, res) => {
    const cmd = req.body?.cmd;

    if (!cmd) {
        return res.status(400).json({ error: "Missing 'cmd' field in request body" });
    }

    // VULNERABILITY: user input passed directly to the shell — no sanitisation.
    exec(cmd, (error, stdout, stderr) => {
        res.json({
            cmd,
            stdout: stdout || "",
            stderr: stderr || "",
            exitCode: error ? error.code ?? 1 : 0,
        });
    });
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => {
    console.log(`[target] Vulnerable demo server running on http://localhost:${PORT}`);
    console.log(`[target] POST /api/execute  { "cmd": "<shell command>" }`);
});

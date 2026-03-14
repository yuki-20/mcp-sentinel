# 🛡️ MCP Sentinel

**Enterprise MCP Security Posture Management & Detonation Platform**

MCP Sentinel is a comprehensive security platform for discovering, analyzing, and hardening Model Context Protocol (MCP) server deployments. It provides static analysis, runtime detonation, policy enforcement, and evidence-grade audit trails.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Sentinel                          │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Discovery│  Static  │ Runtime  │  Policy  │  Evidence   │
│  Layer   │ Analysis │Detonation│  Engine  │  & Audit    │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│Collector │ Scanner  │  Runner  │  Policy  │  Evidence   │
│(4 parsers│(12 detect│(honeytok │(3 bundles│  (REST API  │
│+ watcher)│ families)│+ sandbox)│+ waivers)│  + audit)   │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│                   Core Package                           │
│  Types (18 entities) │ Risk Scoring │ DB │ Formatters    │
├─────────────────────────────────────────────────────────┤
│         CLI (8 commands) │ Web Dashboard (8 pages)       │
└─────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🔍 Discovery (Collector)
- Auto-discover MCP servers from **Claude Desktop**, **Cursor**, **VS Code**, and **Claude Code** configs
- Generic JSON parser for custom configurations
- File-system watcher for continuous monitoring
- Transport and auth posture inference

### 🛡️ Static Analysis (Scanner — 12 Detector Families)
| Detector | Description |
|----------|-------------|
| Secret Scanner | 18 regex patterns + Shannon entropy analysis |
| Startup Command | Detects curl\|sh, sudo, reverse shells, encoded commands |
| Auth Posture | MCP 2025-11-25 spec compliance checks |
| Capability Surface | Overbroad permissions and destructive tool detection |
| Command Injection | exec(), shell:true, eval(), spawn patterns |
| Path Traversal | Unrestricted file ops, directory traversal |
| SSRF | User-controlled URLs, internal IP detection |
| Token Passthrough | Bearer forwarding (forbidden by spec) |
| Tool Poisoning | Deceptive descriptions vs actual capabilities |
| Dependency Risk | Typosquat heuristics, postinstall scripts, provenance |
| Version Drift | Silent privilege creep between versions |
| Network Exfiltration | Beaconing, telemetry libs, hidden uploads |

### 💥 Runtime Detonation (Runner)
- **Honeytoken engine** — 9 canary types (AWS keys, GitHub tokens, SSH keys, webhooks, metadata)
- **Synthetic workspace** — Fake repos, credentials, and project files
- **Protocol probes** — Traversal, injection, and fuzz testing
- **Evidence bundles** — SHA-256 signed attestations

### 📜 Policy Engine
- JSON-based rules with compound AND/OR conditions
- 3 built-in bundles: **Strict**, **Standard**, **Permissive**
- Waiver system with owner, reason, and expiry
- Dry-run mode for safe evaluation

### 📊 Risk Scoring
```
Risk = impact × exploitability × exposure × confidence
```
- Severity → impact mapping
- Transport → exposure mapping  
- Auth posture → exploitability mapping
- Compensating controls reduce adjusted score

## 📦 Packages

| Package | Description |
|---------|-------------|
| `@mcp-sentinel/core` | Shared types, scoring, formatters, database |
| `@mcp-sentinel/collector` | Config parsers and discovery |
| `@mcp-sentinel/scanner` | 12 static analysis detectors |
| `@mcp-sentinel/runner` | Runtime detonation and honeytokens |
| `@mcp-sentinel/policy` | Policy engine and built-in bundles |
| `@mcp-sentinel/evidence` | Evidence REST API server |
| `@mcp-sentinel/cli` | Terminal interface (8 commands) |
| `@mcp-sentinel/web` | React dashboard (8 pages) |

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Run a scan
cd packages/cli
npx ts-node src/index.ts scan

# Discover local MCP servers
npx ts-node src/index.ts discover

# Start the web dashboard
cd packages/web
npm install
npm run dev

# Start the evidence API
cd packages/evidence
npx ts-node src/server.ts
```

## 🔬 Research Harness

```bash
cd research

# Generate test dataset
python harness.py dataset

# Run benchmarks
python harness.py benchmark -d datasets/mcp_security_dataset.json

# Generate report
python harness.py report -r results/benchmark_results.json
```

## 📄 Output Formats

- **JSON** — Machine-readable scan results
- **SARIF v2.1.0** — Compatible with GitHub Code Scanning
- **Text** — Human-readable with ANSI colors

## 🛠️ Tech Stack

- **TypeScript** monorepo with npm workspaces
- **React + Vite** for web dashboard
- **Express** for REST API
- **better-sqlite3** for local database
- **Python** for research harness

## 📝 License

MIT

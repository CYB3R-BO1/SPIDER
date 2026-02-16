# SPIDER - Multi-Agent Reverse Engineering Pipeline

**SPIDER** is a research-grade, multi-agent system for automated binary reverse engineering. It ingests executables, performs layered static and dynamic analysis, applies heuristics, and generates human-readable explanations of code.

---

## Features

- **Multi-agent pipeline** - static analysis, dynamic tracing, heuristics, verification, semantic explanation
- **Plugin system** - extensible analysis via dynamically loaded plugins (anti-debug, crypto, entropy, magic patterns, string decoding)
- **Graph-backed storage** - Neo4j for production, in-memory fallback for quick use
- **Constraint solving** - Z3-powered branch feasibility checking and infeasible edge pruning
- **C pseudocode generation** - reconstruct readable C-like code from disassembly
- **Cyclomatic complexity** - per-function CFG complexity metrics
- **JSON export** - full analysis export for interoperability and reporting
- **Snapshot system** - save, load, list, and diff analysis states
- **Cross-platform** - Linux and Windows (dynamic tracing Linux-only)
- **Docker support** - one-command deployment with Neo4j and Redis

---

## Quick Start

```bash
# 1. Set up
python -m venv .venv
source .venv/bin/activate    # Linux
# .venv\Scripts\activate     # Windows
pip install -r requirements.txt

# 2. Run
python main.py                        # Interactive CLI
python main.py path/to/binary         # Direct analysis

# 3. Docker (full stack)
cd docker && docker compose up -d
```

See [SETUP.md](SETUP.md) for detailed installation instructions.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `load <binary>` | Analyze a binary |
| `list funcs` | List discovered functions |
| `info <addr>` | Function details |
| `blocks / insns / edges` | CFG exploration |
| `explain [level] <addr>` | Semantic summary (simple/medium/deep) |
| `pseudocode <addr>` | C-like pseudocode |
| `complexity [addr]` | Cyclomatic complexity metrics |
| `verify` | Run verifier (branch feasibility, unsafe patterns) |
| `export <path>` | Export analysis to JSON |
| `plugins list / run` | Manage analysis plugins |
| `snapshot save/list/show/diff` | Manage analysis snapshots |
| `status` | Check tool availability |

---

## Project Structure

```
├── main.py                  # Entry point
├── config.yml               # Default configuration
├── core/                    # Config, capabilities, events, IR
├── agents/                  # Analysis agents
├── orchestrator/            # Pipeline controller
├── storage/                 # Neo4j, in-memory, SQLite, snapshots
├── bus/                     # Event bus (Redis + local)
├── plugins/                 # Analysis plugins
├── analysis/                # Complexity, export, constraint passes
├── ui/                      # Interactive CLI
├── docker/                  # Docker deployment
└── tests/                   # Test binaries
```

---

## Documentation

- **[SETUP.md](SETUP.md)** - Installation guide (Linux + Windows)
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and data flow
- **[PLUGINS.md](PLUGINS.md)** - Plugin development guide

---

## Requirements

- Python 3.10+
- Optional: radare2, GDB (Linux), Neo4j, Redis, z3-solver

All optional dependencies have graceful fallbacks.

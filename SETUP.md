# SPIDER - Setup Guide

Complete setup instructions for **Linux** and **Windows**.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | 3.11 recommended |
| pip | Latest | `python -m pip install --upgrade pip` |
| Git | Any | For cloning the repository |

### Optional Tools (enable additional agents)

| Tool | Agent | Notes |
|------|-------|-------|
| radare2 + r2pipe | Static analysis | Core disassembly engine |
| GDB + pygdbmi | Dynamic tracing | Linux only |
| Neo4j | Graph storage | Falls back to in-memory if absent |
| Redis | Event bus | Falls back to local bus if absent |
| z3-solver | Verification | Falls back to stub if absent |

---

## 1. Clone and Set Up

```bash
git clone https://github.com/CYB3R-BO1/SPIDER.git
cd SPIDER
```

### Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Windows (cmd)
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

---

## 2. Configure Environment

Copy the example environment file and edit as needed:

```bash
cp .env.example .env
```

The `.env` file supports:
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` - Neo4j connection
- `REDIS_HOST`, `REDIS_PORT` - Redis connection
- `R2_PATH`, `GDB_PATH` - Custom tool paths
- `PIPELINE_EVENT_TIMEOUT` - Pipeline timeout in seconds

> **Note:** SPIDER works fully without Neo4j and Redis. They are optional.

---

## 3. Install Optional Tools

### radare2 (recommended)

**Linux:**
```bash
git clone https://github.com/radareorg/radare2.git
cd radare2 && sys/install.sh
pip install r2pipe
```

**Windows:**
Download from [radare2 releases](https://github.com/radareorg/radare2/releases) and add to PATH.
```cmd
pip install r2pipe
```

### GDB (Linux only)
```bash
# Debian/Ubuntu
sudo apt install gdb
pip install pygdbmi
```

### Z3 Solver
```bash
pip install z3-solver
```

### Neo4j
```bash
# Docker (recommended):
docker run -d -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:5-community

# Or use docker/compose.yml for full stack:
cd docker && docker compose up -d
```

### Redis
```bash
# Docker:
docker run -d -p 6379:6379 redis:7-alpine

# Or included in docker/compose.yml
```

---

## 4. Run SPIDER

### Interactive CLI (default)
```bash
python main.py
```

### Direct binary analysis
```bash
python main.py path/to/binary
```

### Docker (full stack)
```bash
cd docker
docker compose up -d
docker compose exec spider python main.py
```

---

## 5. Verify Installation

Once inside the CLI, type `status` to check tool availability:

```
spider> status

Tool/Service Status:
  [+] r2pipe: OK
  [+] radare2: OK
  [-] gdb: NOT FOUND
  [-] pygdbmi: NOT FOUND
  [-] neo4j: NOT FOUND
  [-] redis: NOT FOUND
  [+] z3-solver: OK
```

Tools marked `NOT FOUND` will use fallback implementations.

---

## 6. Quick Test

```
spider> load tests/binaries/ret
spider> list funcs
spider> complexity
spider> plugins list
spider> export report.json
spider> quit
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Activate venv and run `pip install -r requirements.txt` |
| `r2pipe` import fails | Install radare2 and add to PATH |
| Neo4j connection refused | Start Neo4j or ignore - in-memory fallback is used |
| Pipeline timeout | Increase `PIPELINE_EVENT_TIMEOUT` in `.env` |
| Windows path errors | Use forward slashes or raw strings in paths |

# SPIDER - Architecture

## Overview

SPIDER is a **multi-agent reverse engineering pipeline** that ingests binary executables, performs layered analysis, and produces human-readable explanations.

```
┌─────────────────────────────────────────────────────────────┐
│                     MasterAgent (Orchestrator)              │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  Static   │→│Heuristics│→│  Verifier │→│  Dynamic   │  │
│  │  Agent    │  │  Agent   │  │  Agent   │  │  Agent     │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
│       ↓              ↓             ↓             ↓         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  Plugins  │  │ Semantic │  │   CGen   │  │ Constraint│  │
│  │  Manager  │  │  Agent   │  │  Agent   │  │   Pass    │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Event Bus (Redis / Local)           │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌──────────────────────┐  ┌────────────────────────────┐  │
│  │  Graph Store          │  │  SQLite Store + Snapshots  │  │
│  │  (Neo4j / In-Memory)  │  │                            │  │
│  └──────────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Pipeline Flow

1. **Static Analysis** - `StaticAgent` uses radare2 to disassemble the binary, extracting functions, basic blocks, instructions, and control flow edges
2. **Post-Processing** - `StaticPost` cleans the CFG: removes unreachable blocks, folds linear chains, detects switch tables
3. **Heuristic Analysis** - `HeuristicsAgent` applies pattern matching for loops, crypto, prologues/epilogues, and computes dominators
4. **Verification** - `VerifierAgent` + `Z3Agent` check branch feasibility and detect unsafe patterns (buffer overflows, format strings)
5. **Dynamic Tracing** - `DynamicAgent` uses GDB to trace execution, recording hit blocks, register states, and syscalls
6. **Plugin Execution** - `PluginManager` runs all loaded analysis plugins (anti-debug, crypto, magic patterns, string decoding, entropy)
7. **Semantic Explanation** - `SemanticAgent` generates human-readable function summaries at multiple detail levels
8. **Snapshot** - `SnapshotManager` saves the analysis state for later comparison

---

## Module Reference

| Module | Location | Purpose |
|--------|----------|---------|
| `core/` | `core/` | Configuration, capabilities, events, IR data classes |
| `agents/` | `agents/` | All analysis agents |
| `bus/` | `bus/` | Event bus (Redis + local fallback) |
| `storage/` | `storage/` | Graph store (Neo4j + in-memory), SQLite, snapshots |
| `orchestrator/` | `orchestrator/` | MasterAgent pipeline controller |
| `plugins/` | `plugins/` | Dynamically loaded analysis plugins |
| `analysis/` | `analysis/` | Constraint passes, complexity metrics, export |
| `ui/` | `ui/` | Interactive CLI |

---

## Event Bus

The event bus decouples agent communication:

| Event | Publisher | Subscribers |
|-------|-----------|-------------|
| `STATIC_ANALYSIS_COMPLETE` | StaticAgent | MasterAgent |
| `DYNAMIC_TRACE_READY` | DynamicAgent | MasterAgent |
| `HEURISTICS_DONE` | HeuristicsAgent | - |
| `SEMANTIC_DONE` | SemanticAgent | - |
| `VERIFICATION_ISSUE` | VerifierAgent | - |

---

## Capability System

Each agent declares `CAPABILITIES` (a set of `Capability` enum values). Before invoking an agent, the orchestrator checks with `enforce_capability()` to prevent unauthorized operations.

| Capability | Agents |
|-----------|--------|
| `STATIC_READ` | HeuristicsAgent, SemanticAgent |
| `STATIC_WRITE` | StaticAgent |
| `DYNAMIC_EXECUTE` | DynamicAgent |
| `VERIFY` | VerifierAgent |
| `SEMANTIC_REASON` | SemanticAgent |
| `SNAPSHOT` | SnapshotManager |
| `PLUGIN_ANALYSIS` | PluginManager |

---

## Storage Layer

**Graph Store** stores the program's structure:
- **Function** nodes with address, name, properties
- **BasicBlock** nodes with address, size
- **Instruction** nodes with address, mnemonic, operands
- **FLOW** edges (CFG), **CALL** edges, **CONTAINS**/**IN** relationships

Falls back to `MemoryGraphStore` (Python dicts) when Neo4j is unavailable.

**SQLite Store** persists metadata, logs, and analysis snapshots.

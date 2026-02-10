# SPIDER

SPIDER is a multi-agent reverse engineering pipeline that combines static analysis, dynamic tracing, constraint solving, and graph-based reasoning.

**What It Does**
1. Ingests binaries via `radare2` and builds a control-flow graph (CFG) in Neo4j.
2. Applies heuristics for loops, crypto patterns, stack frames, and function classification.
3. Traces runtime execution with GDB MI to validate static CFG edges.
4. Runs constraint and verification passes to prune infeasible edges and flag suspect control flow.
5. Produces human-readable explanations of functions.

**Project Structure**
- `agents/`: Analysis agents (static, dynamic, heuristics, verifier, semantic, z3).
- `analysis/`: Constraint passes and post-processing.
- `storage/`: Graph store (Neo4j) and snapshot metadata (SQLite).
- `orchestrator/`: Event-driven pipeline control.
- `tests/`: Test scaffolding (if present).

**Requirements**
- Python 3.10+
- Neo4j (graph storage)
- Redis (event bus)
- radare2 (static analysis)
- GDB with MI support (dynamic tracing)

Install Python dependencies:
```bash
python -m pip install -r requirements.txt
```

**Quick Start**
1. Start Neo4j and Redis.
2. Run static analysis with `StaticAgent` to populate the graph.
3. Run `HeuristicsAgent`, `Z3` constraint pass, and `VerifierAgent` as needed.
4. Use `SemanticAgent.explain_function()` for summaries.

**Notes**
- Dynamic tracing requires a debuggable binary and GDB MI support.
- Snapshotting stores metadata and file references in SQLite (see `storage/snapshots.py`).

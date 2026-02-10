import shlex

from core import load_env
from orchestrator.master_agent import MasterAgent
from agents.semantic_agent import SemanticAgent
from agents.cgen_agent import CCodeGeneratorAgent
from storage.graph_store import GraphStore
from storage.sqlite_store import SQLiteStore
from storage.snapshots import SnapshotManager


def _parse_addr(text: str) -> int:
    text = text.strip()
    if text.startswith("0x") or text.startswith("-0x"):
        return int(text, 16)
    return int(text, 10)


def main():
    load_env()
    master = MasterAgent()
    graph = master.graph_store
    semantic = master.semantic_agent
    cgen = CCodeGeneratorAgent(graph)
    snapshots = master.snapshots

    # Allow running an initial load when invoked as a module with args,
    # e.g. `python -m ui.cli load tests/binaries/run`
    import sys

    current_binary = None
    if len(sys.argv) > 1:
        # support both: `ui.cli load <path>` and `ui.cli <path>`
        if sys.argv[1] == "load" and len(sys.argv) > 2:
            initial_path = sys.argv[2]
        else:
            initial_path = sys.argv[1]

        current_binary = initial_path
        print(f"[CLI] Running pipeline for {current_binary}...")
        master.run_pipeline(current_binary)

    print("SPIDER CLI. Type 'help' for commands.")
    while True:
        try:
            line = input("spider> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in {"exit", "quit"}:
            break
        if line == "help":
            print(
                "Commands:\n"
                "  load <binary>\n"
                "  list funcs\n"
                "  explain <func_addr>\n"
                "  pseudocode <func_addr>\n"
                "  trace\n"
                "  snapshot save <name>\n"
                "  snapshot list\n"
                "  quit"
            )
            continue

        parts = shlex.split(line)
        if not parts:
            continue

        cmd = parts[0]
        args = parts[1:]

        if cmd == "load" and args:
            current_binary = args[0]
            print(f"[CLI] Running pipeline for {current_binary}...")
            master.run_pipeline(current_binary)
            continue

        if cmd == "list" and args and args[0] == "funcs":
            funcs = graph.fetch_functions()
            for f in funcs:
                print(f"0x{f['addr']:x}  {f.get('name')}")
            continue

        if cmd == "explain" and args:
            try:
                addr = _parse_addr(args[0])
            except Exception:
                print("Invalid function address.")
                continue
            result = semantic.explain_function(addr)
            print(result.get("summary", ""))
            for step in result.get("steps", []):
                print(f" - {step}")
            continue

        if cmd == "pseudocode" and args:
            try:
                addr = _parse_addr(args[0])
            except Exception:
                print("Invalid function address.")
                continue
            print(cgen.generate(addr))
            continue

        if cmd == "trace":
            if not current_binary:
                print("No binary loaded.")
                continue
            print(f"[CLI] Tracing {current_binary}...")
            master.run_pipeline(current_binary)
            continue

        if cmd == "snapshot" and args:
            if args[0] == "save" and len(args) >= 2:
                name = args[1]
                snapshots.create_snapshot(name, description="CLI snapshot")
                print(f"[CLI] Snapshot saved: {name}")
                continue
            if args[0] == "list":
                for s in snapshots.list_snapshots():
                    print(f"{s['name']}  {s['created_at']}")
                continue

        print("Unknown command. Type 'help' for usage.")


if __name__ == "__main__":
    main()

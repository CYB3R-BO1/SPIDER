import threading
import time
from datetime import datetime, timezone

from bus.event_bus import EventBus
from core import load_env
from core.config import get_config
from core.capabilities import Capability, enforce_capability
from storage.graph_store import create_graph_store
from storage.sqlite_store import SQLiteStore
from storage.snapshots import SnapshotManager
from plugins import PluginManager
from agents.static_agent import StaticAgent
from agents.heuristics_agent import HeuristicsAgent
from agents.verifier_agent import VerifierAgent
from agents.dynamic_agent import DynamicAgent
from agents.semantic_agent import SemanticAgent


class MasterAgent:
    """
    Controls the multi-agent pipeline.
    Listens for events and triggers appropriate agents.
    """

    def __init__(self):
        load_env()
        config = get_config()
        self.bus = EventBus()
        self.state = {}
        self._state_lock = threading.Lock()
        self._done_event = threading.Event()
        self.event_timeout_seconds = float(
            config.get("pipeline", {}).get("event_timeout_seconds", 10.0)
        )

        neo4j_cfg = config.get("neo4j", {})
        self.graph_store = create_graph_store(
            neo4j_cfg.get("uri", "bolt://localhost:7687"),
            neo4j_cfg.get("user", "neo4j"),
            neo4j_cfg.get("password", "neo4j"),
            neo4j_cfg.get("database", "neo4j"),
        )
        self.sqlite_store = SQLiteStore(
            db_path=config.get("sqlite", {}).get("db_path", "storage/metadata.db")
        )
        self.snapshots = SnapshotManager(self.sqlite_store, graph_store=self.graph_store)
        self.plugins = PluginManager()

        self.static_agent = StaticAgent(self.graph_store, self.bus)
        self.heuristics_agent = HeuristicsAgent(self.graph_store, self.bus)
        self.verifier_agent = VerifierAgent(self.graph_store, self.bus)
        self.dynamic_agent = DynamicAgent(self.graph_store, self.bus)
        self.semantic_agent = SemanticAgent(self.graph_store, self.bus)

        self.bus.subscribe("STATIC_ANALYSIS_COMPLETE", self._handle_static_done)
        self.bus.subscribe("DYNAMIC_TRACE_READY", self._handle_dynamic_done)

    # ---------------------------
    # Event handlers
    # ---------------------------

    def _handle_static_done(self, event, payload):
        with self._state_lock:
            if not self.state.get("active"):
                return
            if self.state.get("static_done"):
                return
            self.state["static_done"] = True
            self.state["last_event_time"] = time.monotonic()

        print("[Master] Static analysis complete. Running heuristics...")
        if enforce_capability(self.heuristics_agent, Capability.STATIC_READ):
            self.heuristics_agent.run()

        print("[Master] Verifying static contradictions...")
        if enforce_capability(self.verifier_agent, Capability.VERIFY):
            self.verifier_agent.verify_basicblock_edges()

        print("[Master] Starting dynamic tracing...")
        run_id = self.state.get("run_id")
        binary_path = self.state.get("binary_path")
        if binary_path and enforce_capability(self.dynamic_agent, Capability.DYNAMIC_EXECUTE):
            self.dynamic_agent.run(binary_path, run_id=run_id)

    def _handle_dynamic_done(self, event, payload):
        with self._state_lock:
            if not self.state.get("active"):
                return
            if self.state.get("dynamic_done"):
                return
            self.state["dynamic_done"] = True
            self.state["last_event_time"] = time.monotonic()

        print("[Master] Dynamic trace ready. Verifying runtime edges...")
        if enforce_capability(self.verifier_agent, Capability.VERIFY):
            self.verifier_agent.verify_basicblock_edges()

        print("[Master] Running plugins...")
        if enforce_capability(self.plugins, Capability.PLUGIN_ANALYSIS):
            self.plugins.load_plugins()
            for func in self.graph_store.fetch_functions():
                addr = func.get("addr")
                if addr is None:
                    continue
                self.plugins.run_all(self.graph_store, addr)

        print("[Master] Generating semantic explanations...")
        if enforce_capability(self.semantic_agent, Capability.SEMANTIC_REASON):
            semantic_results = {}
            for func in self.graph_store.fetch_functions():
                addr = func.get("addr")
                if addr is None:
                    continue
                semantic_results[addr] = self.semantic_agent.explain_function(addr)
            with self._state_lock:
                self.state["semantic_results"] = semantic_results
            self.graph_store.set_semantic_summaries(semantic_results)

        print("[Master] Creating snapshot...")
        snapshot_name = self.state.get("snapshot_name")
        if enforce_capability(self.snapshots, Capability.SNAPSHOT):
            self.snapshots.create_snapshot(
                snapshot_name,
                description="Pipeline snapshot",
            )

        print("[Master] Pipeline complete.")
        with self._state_lock:
            self.state["active"] = False
        self._done_event.set()

    # ---------------------------
    # Pipeline entry point
    # ---------------------------

    def run_pipeline(self, binary_path: str):
        with self._state_lock:
            self.state = {
                "active": True,
                "binary_path": binary_path,
                "run_id": f"run_{int(time.time())}",
                "snapshot_name": f"snapshot_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
                "static_done": False,
                "dynamic_done": False,
                "last_event_time": time.monotonic(),
            }
            self._done_event.clear()

        print("[Master] Clearing previous graph state...")
        self.graph_store.clear_graph()

        print("[Master] Launching static analysis...")
        if enforce_capability(self.static_agent, Capability.STATIC_WRITE):
            self.static_agent.run(binary_path)

        # With LocalEventBus, handlers fire synchronously inside
        # static_agent.run(), so the pipeline may already be done.
        if self._done_event.is_set():
            return

        print("[Master] Waiting for pipeline completion...")
        while not self._done_event.is_set():
            with self._state_lock:
                last_event = self.state.get("last_event_time", time.monotonic())
                active = self.state.get("active", False)
            if not active:
                break
            if time.monotonic() - last_event > self.event_timeout_seconds:
                print(
                    f"[Master] Pipeline timeout (no events in {self.event_timeout_seconds}s)."
                )
                with self._state_lock:
                    self.state["active"] = False
                break
            time.sleep(0.1)

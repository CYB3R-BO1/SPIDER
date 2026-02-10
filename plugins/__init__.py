import importlib.util
import os
import time
from typing import Dict, List, Optional

from core.capabilities import Capability


class PluginManager:
    """
    Dynamically loads analysis plugins from the plugins directory.
    Each plugin must expose analyze(graph_store, func_addr) -> dict.
    """

    CAPABILITIES = {Capability.PLUGIN_ANALYSIS}

    def __init__(self, plugins_dir: Optional[str] = None):
        self.plugins_dir = plugins_dir or os.path.dirname(__file__)
        self._plugins = {}

    def load_plugins(self):
        self._plugins = {}
        for filename in os.listdir(self.plugins_dir):
            if not filename.endswith(".py"):
                continue
            if filename.startswith("_") or filename == "__init__.py":
                continue
            path = os.path.join(self.plugins_dir, filename)
            module_name = f"plugin_{os.path.splitext(filename)[0]}_{int(time.time()*1000)}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                analyze = getattr(module, "analyze", None)
                if callable(analyze):
                    self._plugins[filename] = analyze
            except Exception as exc:
                print(f"[PluginManager] Failed to import {filename}: {exc}")
                continue

    def list_plugins(self) -> List[str]:
        return sorted(self._plugins.keys())

    def run_all(self, graph_store, func_addr: int) -> Dict:
        facts: Dict = {}
        for name, analyze in self._plugins.items():
            try:
                result = analyze(graph_store, func_addr)
                if isinstance(result, dict):
                    facts.update(result)
            except Exception as exc:
                print(f"[PluginManager] Plugin {name} failed: {exc}")
                continue
        if facts:
            graph_store.set_plugin_facts(func_addr, facts)
        return facts

from typing import Optional, Set, Tuple

from storage.graph_store import GraphStore
from bus.event_bus import EventBus


class VerifierAgent:
    """
    Validates claims made by AI or heuristic agents.
    Responsibilities:
    - Cross-check semantic explanations with static/dynamic facts.
    - Use Z3Agent to verify logic conditions.
    - Detect contradictions and request re-analysis.
    - Publish VERIFY_RESULT.
    """

    def __init__(self, graph_store: GraphStore, bus: Optional[EventBus] = None):
        self.g = graph_store
        self.bus = bus

    def verify_basicblock_edges(self):
        static_edges = set(self.g.fetch_all_flow_edges())
        runtime_edges = set(self.g.fetch_runtime_flow_edges())

        suspect = 0
        for edge in static_edges:
            if edge not in runtime_edges:
                self.g.mark_flow_edge_suspect(edge[0], edge[1])
                suspect += 1

        if self.bus is not None:
            self.bus.publish(
                "VERIFY_RESULT",
                {
                    "suspect_edges": suspect,
                    "static_edges": len(static_edges),
                    "runtime_edges": len(runtime_edges),
                },
            )

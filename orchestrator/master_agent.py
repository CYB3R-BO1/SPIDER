from bus.event_bus import EventBus


class MasterAgent:
    """
    Controls the multi-agent pipeline.
    Listens for events and triggers appropriate agents.
    """

    def __init__(self):
        self.bus = EventBus()
        self.state = {}

        # Example subscription
        self.bus.subscribe("STATIC_ANALYSIS_COMPLETE", self.handle_static_done)

    def handle_static_done(self, event, payload):
        print(f"[Master] Static analysis complete for {payload}")

    def run(self):
        print("[Master] System ready. Waiting for events...")
        while True:
            pass  # event-driven loop

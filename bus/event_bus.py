import json
import os
import threading
import redis


class EventBus:
    """
    Minimal event bus using Redis Pub/Sub.
    Agents publish JSON payloads.
    Subscribers listen in background threads.
    """

    def __init__(self, host=None, port=None):
        if host is None:
            host = os.getenv("REDIS_HOST", "localhost")
        if port is None:
            port = int(os.getenv("REDIS_PORT", "6379"))
        self.client = redis.Redis(host=host, port=port, decode_responses=True)
        self.pubsub = self.client.pubsub()

    def publish(self, event_name: str, payload: dict):
        message = json.dumps(payload)
        self.client.publish(event_name, message)

    def subscribe(self, event_name: str, handler):
        """
        Subscribe a handler(event_name, payload_dict) to a channel.
        Runs handler in a background thread.
        """
        def _listener():
            self.pubsub.subscribe(event_name)
            for msg in self.pubsub.listen():
                if msg["type"] == "message":
                    try:
                        data = json.loads(msg["data"])
                        handler(event_name, data)
                    except Exception as e:
                        print("Handler error:", e)

        t = threading.Thread(target=_listener, daemon=True)
        t.start()

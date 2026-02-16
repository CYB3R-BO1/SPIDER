import json
import threading
from collections import defaultdict
from typing import Callable, Dict, List, Optional

from core.config import get_config


class LocalEventBus:
    """
    In-memory event bus using threading.
    No external dependencies required.
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def publish(self, event_name: str, payload: dict):
        with self._lock:
            handlers = list(self._subscribers.get(event_name, []))
        for handler in handlers:
            try:
                handler(event_name, payload)
            except Exception as e:
                print(f"[EventBus] Handler error on '{event_name}': {e}")

    def subscribe(self, event_name: str, handler: Callable):
        with self._lock:
            self._subscribers[event_name].append(handler)


class RedisEventBus:
    """
    Event bus using Redis Pub/Sub.
    Agents publish JSON payloads.
    Each subscriber gets its own pubsub connection for thread safety.
    """

    def __init__(self, host: str = "localhost", port: int = 6379):
        import redis
        self._redis_mod = redis
        self._host = host
        self._port = port
        self.client = redis.Redis(
            host=host, port=port, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )

    def publish(self, event_name: str, payload: dict):
        message = json.dumps(payload)
        self.client.publish(event_name, message)

    def subscribe(self, event_name: str, handler: Callable):
        """
        Subscribe a handler(event_name, payload_dict) to a channel.
        Each subscription gets its own pubsub connection and listener thread.
        """
        # Create a separate pubsub per subscriber for thread safety
        sub_client = self._redis_mod.Redis(
            host=self._host, port=self._port, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        ps = sub_client.pubsub()

        def _listener():
            ps.subscribe(event_name)
            for msg in ps.listen():
                if msg["type"] == "message":
                    try:
                        data = json.loads(msg["data"])
                        handler(event_name, data)
                    except Exception as e:
                        print(f"[EventBus] Handler error on '{event_name}': {e}")

        t = threading.Thread(target=_listener, daemon=True)
        t.start()



def EventBus(host: Optional[str] = None, port: Optional[int] = None):
    """
    Factory: returns a Redis-backed bus when Redis is available,
    otherwise falls back to an in-memory local bus.
    """
    config = get_config()
    if host is None:
        host = config.get("redis", {}).get("host", "localhost")
    if port is None:
        port = int(config.get("redis", {}).get("port", 6379))
    try:
        import redis as _redis
        client = _redis.Redis(
            host=host, port=port, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        client.ping()
        print("[EventBus] Connected to Redis.")
        return RedisEventBus(host, port)
    except Exception:
        print("[EventBus] Redis unavailable - using local in-memory bus.")
        return LocalEventBus()

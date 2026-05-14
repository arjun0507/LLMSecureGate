import logging
from collections import Counter
from threading import Lock
from typing import Dict


LOGGER = logging.getLogger("securegate")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: Counter[str] = Counter()

    def inc(self, key: str, value: int = 1) -> None:
        with self._lock:
            self._counters[key] += value

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)


METRICS = MetricsRegistry()

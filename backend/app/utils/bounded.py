"""
Bounded, thread-safe, dict-like store with LRU eviction and optional
sliding TTL.

Every per-session structure in the backend (histories, detectors, kill-chain
state, containment ...) lives in one of these, so memory use stays bounded no
matter how many sessions an attacker opens.
"""

import threading
import time
from collections import OrderedDict

_MISSING = object()


class BoundedStore:

    def __init__(self, max_items: int = 5000, ttl_seconds: float | None = None, clock=time.monotonic):
        self.max_items = max(1, int(max_items))
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._data: OrderedDict = OrderedDict()   # key -> (expires_at | None, value)
        self._lock = threading.RLock()

    # --------------------------------------------------

    def _expiry(self):
        return None if not self.ttl_seconds else self._clock() + self.ttl_seconds

    def _purge(self):
        if not self.ttl_seconds:
            return

        now = self._clock()
        expired = [k for k, (exp, _v) in self._data.items() if exp is not None and exp <= now]

        for key in expired:
            del self._data[key]

    def _evict(self):
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)

    # --------------------------------------------------

    def __setitem__(self, key, value):
        with self._lock:
            self._purge()
            self._data[key] = (self._expiry(), value)
            self._data.move_to_end(key)
            self._evict()

    def get(self, key, default=None):
        with self._lock:
            self._purge()
            entry = self._data.get(key, _MISSING)

            if entry is _MISSING:
                return default

            self._data[key] = (self._expiry(), entry[1])
            self._data.move_to_end(key)

            return entry[1]

    def __getitem__(self, key):
        value = self.get(key, _MISSING)

        if value is _MISSING:
            raise KeyError(key)

        return value

    def setdefault(self, key, default=None):
        with self._lock:
            value = self.get(key, _MISSING)

            if value is _MISSING:
                self[key] = default
                return default

            return value

    def __contains__(self, key):
        with self._lock:
            self._purge()
            return key in self._data

    def pop(self, key, default=_MISSING):
        with self._lock:
            entry = self._data.pop(key, _MISSING)

            if entry is _MISSING:
                if default is _MISSING:
                    raise KeyError(key)
                return default

            return entry[1]

    def clear(self):
        with self._lock:
            self._data.clear()

    def keys(self):
        with self._lock:
            self._purge()
            return list(self._data.keys())

    def items(self):
        with self._lock:
            self._purge()
            return [(k, v) for k, (_e, v) in self._data.items()]

    def __len__(self):
        with self._lock:
            self._purge()
            return len(self._data)

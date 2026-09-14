"""Fail-closed, bounded request admission with constant work per request."""
import threading
import time


class AdmissionLimiter:
    def __init__(self, max_entries=100000, clock=time.monotonic):
        self.entries = {}
        self.max_entries = max_entries
        self.clock = clock
        self.next_cleanup = 0
        self.lock = threading.Lock()

    def allow(self, key, maximum, seconds=60):
        with self.lock:
            now = self.clock()
            if now >= self.next_cleanup:
                self.entries = {k: v for k, v in self.entries.items() if v[1] > now}
                self.next_cleanup = now + 60
            entry = self.entries.get(key)
            if entry and entry[1] <= now:
                del self.entries[key]
                entry = None
            if entry is None:
                if len(self.entries) >= self.max_entries:
                    return False
                entry = [0, now + seconds]
                self.entries[key] = entry
            if entry[0] >= maximum:
                return False
            entry[0] += 1
            return True

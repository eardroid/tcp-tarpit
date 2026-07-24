import threading
import time
from collections import defaultdict, deque

from config import HIT_THRESHOLD, HIT_WINDOW


class ScannerDetector:
    def __init__(self, hit_window=HIT_WINDOW, threshold=HIT_THRESHOLD):
        self.hit_window = hit_window
        self.threshold = threshold
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, source_ip, destination_port, now=None):
        if now is None:
            now = time.time()

        with self.lock:
            port_hits = self.hits[source_ip]
            while port_hits and now - port_hits[0][0] > self.hit_window:
                port_hits.popleft()

            port_hits.append((now, destination_port))
            distinct_ports = len({port for _, port in port_hits})
            classification = "scanner" if distinct_ports >= self.threshold else "normal"
            return classification, distinct_ports

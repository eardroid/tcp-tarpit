"""Safety rails: caps, rate limit, sticky ttl, banner fallback.

Runs with plain python, no root, no scapy needed (we stub it).
Usage:  python3 tests/test_safety.py
"""
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# packet_handler needs scapy at import time, so give it a tiny fake.
fake_scapy = types.ModuleType("scapy")
fake_all = types.ModuleType("scapy.all")


class FakeTCP:
    def __init__(self, sport=40000, dport=22, seq=1000, ack=0, flags=2, window=64240):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window

    def __truediv__(self, other):
        return self


class FakeIP:
    def __init__(self, payload=None, src="192.0.2.9", dst="198.51.100.7",
                 ttl=64, tcp=None):
        if isinstance(payload, FakeIP):
            self.__dict__.update(payload.__dict__)
            return
        self.src = src
        self.dst = dst
        self.ttl = ttl
        self.tcp = tcp or FakeTCP()

    def haslayer(self, kind):
        return kind is FakeTCP

    def __getitem__(self, kind):
        assert kind is FakeTCP
        return self.tcp

    def __truediv__(self, other):
        return self


sent = []
fake_all.IP = FakeIP
fake_all.TCP = FakeTCP
fake_all.send = lambda pkt, verbose=False: sent.append(pkt)
fake_scapy.all = fake_all
sys.modules["scapy"] = fake_scapy
sys.modules["scapy.all"] = fake_all

import packet_handler as ph
from packet_handler import PacketHandler
from banners import get_banner
from config import MAX_TRACKED_IPS
from scanner_detector import ScannerDetector


class FakeDB:
    def __init__(self):
        self.rows = []
        self.status = {}

    def add_connection(self, *args):
        self.rows.append(args)
        return len(self.rows)

    def set_status(self, conn_id, status):
        self.status[conn_id] = status


class FakeDribble:
    active = 0
    started = 0

    def active_count(self):
        return self.active

    def start(self, state):
        self.started += 1


class Queued:
    def __init__(self, ip):
        self.ip = ip
        self.accepted = False
        self.dropped = False

    def get_payload(self):
        return self.ip

    def accept(self):
        self.accepted = True

    def drop(self):
        self.dropped = True


def syn(src, sport, dport):
    return Queued(FakeIP(tcp=FakeTCP(sport=sport, dport=dport)))


# 1. unknown ports get a generic banner instead of raising KeyError.
assert get_banner(9999) == b"220 fake service ready\r\n"
assert get_banner(22).startswith(b"SSH-2.0")

# 2. non-trap traffic is accepted, never stored.
h = PacketHandler(FakeDB(), ScannerDetector(), FakeDribble())
q = Queued(FakeIP(tcp=FakeTCP(dport=9999)))
h.process_packet(q)
assert q.accepted and not q.dropped and len(h.states) == 0

# 3. state cap: only MAX_STATES tracked, the rest stay silent.
ph.MAX_STATES = 2
h = PacketHandler(FakeDB(), ScannerDetector(), FakeDribble())
n0 = len(sent)
q1, q2, q3 = syn("192.0.2.9", 40001, 22), syn("192.0.2.9", 40002, 22), syn("192.0.2.9", 40003, 22)
h.process_packet(q1)
h.process_packet(q2)
h.process_packet(q3)
assert len(sent) == n0 + 2  # two SYN-ACKs went out, third got nothing
assert len(h.states) == 2
assert q3.dropped and ("192.0.2.9", 40003, 22) not in h.states
ph.MAX_STATES = 512

# 4. per-ip SYN-ACK rate limit kicks in.
ph.SYNACK_PER_MINUTE = 2
h = PacketHandler(FakeDB(), ScannerDetector(), FakeDribble())
a, b, c = syn("192.0.2.77", 41001, 22), syn("192.0.2.77", 41002, 22), syn("192.0.2.77", 41003, 22)
h.process_packet(a)
h.process_packet(b)
h.process_packet(c)
assert c.dropped and len(h.states) == 2
ph.SYNACK_PER_MINUTE = 20

# 5. idle states get pruned so the dict cant grow forever.
h = PacketHandler(FakeDB(), ScannerDetector(), FakeDribble())
h.process_packet(syn("192.0.2.9", 42001, 22))
assert len(h.states) == 1
key = next(iter(h.states))
h.states[key]["last_seen"] = 5000.0
h._prune_states(5000.0 + 10000)
assert len(h.states) == 0

# 6. fake ttl is steady per ip (comparing two ports must not change it).
h = PacketHandler(FakeDB(), ScannerDetector(), FakeDribble())
first = h._spoof("192.0.2.5")
h._spoof("192.0.2.6")
assert h._spoof("192.0.2.5") == first

# 7. detector forgets quiet ips instead of growing without bound.
d = ScannerDetector()
base = 1000000.0
for i in range(MAX_TRACKED_IPS + 50):
    d.check(f"10.9.{i // 256}.{i % 256}", 22, now=base)
assert len(d.hits) <= MAX_TRACKED_IPS

print("safety rails passed")

import logging
import random
import threading
import time
from collections import deque

from scapy.all import IP, TCP, send

from banners import get_banner
from config import (
    MAX_DRIBBLES,
    MAX_STATES,
    MAX_TRACKED_IPS,
    NORMAL_CLOSE_DELAY,
    STATE_TIMEOUT,
    SYNACK_PER_MINUTE,
    TARPIT_WINDOW,
    TRAP_PORTS,
    TTL_PROFILES,
)


class PacketHandler:
    def __init__(self, database, detector, dribbler):
        self.database = database
        self.detector = detector
        self.dribbler = dribbler
        self.states = {}
        self.lock = threading.Lock()
        self.synack_hits = {}
        self.ttl_cache = {}

    def _key(self, ip_packet, tcp_packet):
        return (ip_packet.src, tcp_packet.sport, tcp_packet.dport)

    def _spoof(self, client_ip):
        # one fake os per source ip. picking randomly per connection looks
        # fake the moment a scanner compares TTLs across two ports.
        cached = self.ttl_cache.get(client_ip)
        if cached is not None:
            return cached
        if len(self.ttl_cache) >= MAX_TRACKED_IPS:
            self.ttl_cache.pop(next(iter(self.ttl_cache)), None)
        name = random.choice(list(TTL_PROFILES))
        profile = (name, TTL_PROFILES[name])
        self.ttl_cache[client_ip] = profile
        return profile

    def _send(self, state, flags, sequence, acknowledgement, window, data=b""):
        reply = (
            IP(src=state["server_ip"], dst=state["client_ip"], ttl=state["spoofed_ttl"])
            / TCP(
                sport=state["server_port"], dport=state["client_port"], flags=flags,
                seq=sequence, ack=acknowledgement, window=window,
            )
            / data
        )
        send(reply, verbose=False)

    def _prune_states(self, now):
        # drop connections idle too long. called on every SYN so a slow
        # leak cant grow this dict forever.
        idle = [k for k, s in self.states.items() if now - s["last_seen"] > STATE_TIMEOUT]
        for k in idle:
            self.states.pop(k, None)

    def _synack_allowed(self, ip, now):
        # per-ip SYN-ACK rate limit. without this, spoofed SYNs turn us
        # into a reflector and a flood fills the db with junk rows.
        if ip not in self.synack_hits and len(self.synack_hits) >= MAX_TRACKED_IPS:
            for old in list(self.synack_hits):
                if not self.synack_hits[old]:
                    del self.synack_hits[old]
                    break
            else:
                self.synack_hits.pop(next(iter(self.synack_hits)), None)
        dq = self.synack_hits.get(ip)
        if dq is None:
            dq = self.synack_hits[ip] = deque()
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= SYNACK_PER_MINUTE:
            return False
        dq.append(now)
        return True

    def _send_synack(self, state):
        window = TARPIT_WINDOW if state["classification"] == "scanner" else 64240
        self._send(state, "SA", state["server_sequence"], state["client_sequence"], window)

    def _close_normal_later(self, key, state, client_sequence):
        # normal conns get one banner + FIN and then we forget them. the
        # small delay happens in a background thread so waiting here never
        # blocks other packets coming in on the queue thread.
        def work():
            time.sleep(NORMAL_CLOSE_DELAY)
            try:
                self._send(
                    state, "FA", state["server_sequence"] + 1, client_sequence, 64240,
                    state["banner"],
                )
            except Exception:
                logging.exception("clean close send failed")
            try:
                self.database.set_status(state["id"], "closed")
            except Exception:
                logging.exception("clean close db update failed")
            with self.lock:
                if self.states.get(key) is state:
                    self.states.pop(key, None)

        threading.Thread(target=work, name=f"close-{state['id']}", daemon=True).start()

    def send_dribble_byte(self, state, byte):
        with self.lock:
            sequence = state["next_server_sequence"]
            acknowledgement = state["client_acknowledgement"]
            state["next_server_sequence"] += len(byte)
        self._send(state, "PA", sequence, acknowledgement, TARPIT_WINDOW, byte)

    def dribble_finished(self, connection_id):
        self.database.set_status(connection_id, "released")

    def _new_connection(self, ip_packet, tcp_packet):
        classification, hit_count = self.detector.check(ip_packet.src, tcp_packet.dport)
        spoofed_os, spoofed_ttl = self._spoof(ip_packet.src)
        status = "trapped" if classification == "scanner" else "normal"
        connection_id = self.database.add_connection(
            ip_packet.src, tcp_packet.dport, tcp_packet.sport, ip_packet.ttl,
            tcp_packet.window, spoofed_os, classification, status,
        )
        state = {
            "id": connection_id,
            "client_ip": ip_packet.src,
            "server_ip": ip_packet.dst,
            "client_port": tcp_packet.sport,
            "server_port": tcp_packet.dport,
            "client_sequence": int(tcp_packet.seq) + 1,
            "server_sequence": random.randint(100000, 4000000000),
            "next_server_sequence": 0,
            "client_acknowledgement": int(tcp_packet.seq) + 1,
            "spoofed_os": spoofed_os,
            "spoofed_ttl": spoofed_ttl,
            "classification": classification,
            "banner": get_banner(tcp_packet.dport),
            "dribble_started": False,
            "closing": False,
            "last_seen": time.time(),
        }
        state["next_server_sequence"] = state["server_sequence"] + 1
        logging.info(
            "connection %s:%s -> %s classified as %s (%d distinct ports)",
            ip_packet.src, tcp_packet.sport, tcp_packet.dport, classification, hit_count,
        )
        return state

    def process_packet(self, queued_packet):
        try:
            packet = IP(queued_packet.get_payload())
            if not packet.haslayer(TCP) or packet[TCP].dport not in TRAP_PORTS:
                queued_packet.accept()
                return

            tcp_packet = packet[TCP]
            flags = int(tcp_packet.flags)
            key = self._key(packet, tcp_packet)

            if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                now = time.time()
                with self.lock:
                    self._prune_states(now)
                    full = len(self.states) >= MAX_STATES
                    allowed = self._synack_allowed(packet.src, now)
                if full or not allowed:
                    # overloaded or this ip is hammering us: stay silent.
                    # dropping (not accepting) keeps the host stack quiet too.
                    queued_packet.drop()
                    return
                state = self._new_connection(packet, tcp_packet)
                with self.lock:
                    self.states[key] = state
                self._send_synack(state)
            else:
                with self.lock:
                    state = self.states.get(key)
                    if state is not None:
                        state["last_seen"] = time.time()
                if state and flags & (0x01 | 0x04):  # FIN or RST
                    self.release(key, state)
                elif state and flags & 0x10:  # ACK
                    # ack number lives in the ack field, not seq. seq is where
                    # the client is sending from, ack is what it got from us.
                    state["client_acknowledgement"] = int(tcp_packet.ack)
                    if state["classification"] == "scanner" and not state["dribble_started"]:
                        if self.dribbler.active_count() < MAX_DRIBBLES:
                            state["dribble_started"] = True
                            self.dribbler.start(state)
                        # else: too many dribbles already, stay quiet and
                        # retry on the next ACK from this client.
                    elif state["classification"] == "normal" and not state.get("closing"):
                        state["closing"] = True
                        self._close_normal_later(key, state, int(tcp_packet.seq))

            # Dropping prevents the host TCP stack from sending its own RST packets.
            queued_packet.drop()
        except Exception:
            logging.exception("packet callback error")
            queued_packet.drop()

    def release(self, key, state):
        with self.lock:
            self.states.pop(key, None)
        if state["dribble_started"]:
            self.dribbler.stop(state["id"])
        else:
            self.database.set_status(state["id"], "released")

import logging
import random
import threading
import time

from scapy.all import IP, TCP, send

from banners import get_banner
from config import NORMAL_CLOSE_DELAY, TRAP_PORTS, TTL_PROFILES


class PacketHandler:
    def __init__(self, database, detector, dribbler):
        self.database = database
        self.detector = detector
        self.dribbler = dribbler
        self.states = {}
        self.lock = threading.Lock()

    def _key(self, ip_packet, tcp_packet):
        return (ip_packet.src, tcp_packet.sport, tcp_packet.dport)

    def _spoof(self):
        name = random.choice(list(TTL_PROFILES))
        return name, TTL_PROFILES[name]

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

    def _send_synack(self, state):
        window = 0 if state["classification"] == "scanner" else 64240
        self._send(state, "SA", state["server_sequence"], state["client_sequence"], window)

    def _send_clean_close(self, state, client_sequence):
        time.sleep(NORMAL_CLOSE_DELAY)
        self._send(
            state, "FA", state["server_sequence"] + 1, client_sequence, 64240,
            state["banner"],
        )

    def send_dribble_byte(self, state, byte):
        with self.lock:
            sequence = state["next_server_sequence"]
            acknowledgement = state["client_acknowledgement"]
            state["next_server_sequence"] += len(byte)
        self._send(state, "PA", sequence, acknowledgement, 0, byte)

    def dribble_finished(self, connection_id):
        self.database.set_status(connection_id, "released")

    def _new_connection(self, ip_packet, tcp_packet):
        classification, hit_count = self.detector.check(ip_packet.src, tcp_packet.dport)
        spoofed_os, spoofed_ttl = self._spoof()
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
                state = self._new_connection(packet, tcp_packet)
                with self.lock:
                    self.states[key] = state
                self._send_synack(state)
            else:
                with self.lock:
                    state = self.states.get(key)
                if state and flags & (0x01 | 0x04):  # FIN or RST
                    self.release(key, state)
                elif state and flags & 0x10:  # ACK
                    state["client_acknowledgement"] = int(tcp_packet.seq)
                    if state["classification"] == "scanner" and not state["dribble_started"]:
                        state["dribble_started"] = True
                        self.dribbler.start(state)
                    elif state["classification"] == "normal":
                        self._send_clean_close(state, int(tcp_packet.seq))
                        self.database.set_status(state["id"], "closed")
                        with self.lock:
                            self.states.pop(key, None)

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

import logging
import subprocess

from config import QUEUE_NUMBER, TRAP_PORTS


class Iptables:
    def __init__(self, queue_number=QUEUE_NUMBER):
        self.queue_number = queue_number

    def _run(self, args, check=True):
        command = ["iptables", "--wait"] + args
        logging.info("iptables: %s", " ".join(command))
        return subprocess.run(command, check=check, capture_output=True, text=True)

    def _input_rule(self, port):
        return [
            "INPUT", "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", "tcp-tarpit-input",
            "-j", "NFQUEUE", "--queue-num", str(self.queue_number),
        ]

    def _output_rule(self, port):
        return [
            "OUTPUT", "-p", "tcp", "--sport", str(port), "--tcp-flags", "RST", "RST",
            "-m", "comment", "--comment", "tcp-tarpit-rst",
            "-j", "DROP",
        ]

    def install(self):
        for port in TRAP_PORTS:
            for rule in (self._input_rule(port), self._output_rule(port)):
                if self._run(["-C"] + rule, check=False).returncode != 0:
                    self._run(["-I"] + rule)
        logging.info("iptables rules installed for %d trap ports", len(TRAP_PORTS))

    def remove(self):
        for port in TRAP_PORTS:
            for rule in (self._input_rule(port), self._output_rule(port)):
                while self._run(["-D"] + rule, check=False).returncode == 0:
                    pass
        logging.info("tcp-tarpit iptables rules removed")

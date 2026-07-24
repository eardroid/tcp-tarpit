from pathlib import Path


TRAP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt",
}

HIT_WINDOW = 10
HIT_THRESHOLD = 3
DRIBBLE_INTERVAL = 10
QUEUE_NUMBER = 1
NORMAL_CLOSE_DELAY = 0.3
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
DEFAULT_DATA_DIR = Path("data")

# Cisco and BSD both normally use an initial TTL of 255.
TTL_PROFILES = {
    "Windows": 128,
    "Linux": 64,
    "Cisco": 255,
    "BSD": 255,
}

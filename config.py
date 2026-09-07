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
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
DEFAULT_DATA_DIR = Path("data")

# safety caps so one flooder cant eat all memory. tweak freely.
MAX_STATES = 512        # max connections tracked at once, rest ignored
STATE_TIMEOUT = 120     # forget connections idle longer than this (seconds)
MAX_DRIBBLES = 64       # max slow-drip threads at once
SYNACK_PER_MINUTE = 20  # max SYN-ACK replies per source ip per minute
MAX_TRACKED_IPS = 4096  # max source ips remembered across detector + handler

# small but nonzero: window 0 makes scanners read us as filtered and
# some stacks wont accept data bytes on a zero window at all.
TARPIT_WINDOW = 128

# Cisco and BSD both normally use an initial TTL of 255.
TTL_PROFILES = {
    "Windows": 128,
    "Linux": 64,
    "Cisco": 255,
    "BSD": 255,
}

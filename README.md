# TCP Tarpit

A small Linux TCP tarpit for common scanned ports.

It uses `iptables` and `NFQUEUE` to catch incoming TCP connections, classifies
sources that touch several trap ports in a short window, and slows those
connections by sending banner bytes very slowly.

## Why I Built It

I wanted a small project for experimenting with packet handling, fake service
banners, and basic scanner detection. It is meant for lab use on a machine I
control.

## Features

- Trap ports for common services like SSH, HTTP, MySQL, RDP, and VNC.
- Simple per-IP scanner detection based on distinct ports hit within ten seconds.
- Crafted TCP replies with fake service banners.
- Slow byte-by-byte banner sending for sources classified as scanners.
- SQLite connection history and counters.
- Terminal dashboard and optional Flask web dashboard.
- Cleanup of the `iptables` rules it installs.

## Installation

This is Linux-only. It needs root access, `iptables`, NFQUEUE support, and raw packets.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-dev build-essential \
  libnetfilter-queue-dev iptables nmap netcat-openbsd curl

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
sudo modprobe nfnetlink_queue
```

## Usage

Start the tarpit:

```bash
sudo .venv/bin/python main.py
```

Or use the helper script:

```bash
sudo bash run.sh
```

The terminal dashboard starts by default. The web dashboard listens on `http://127.0.0.1:5000` (pass `--web-host 0.0.0.0` to expose it on the LAN).

Stop it with `Ctrl+C`, or from another shell:

```bash
sudo bash stop.sh
```

Local tests that do not need root:

```bash
python3 tests/test_normal_user.py
python3 tests/test_scanner.py
python3 tests/test_database.py
```

Network tests need a separate scanner host:

```bash
bash tests/test_netcat.sh TARGET_IP
bash tests/test_curl.sh TARGET_IP
bash tests/test_nmap.sh TARGET_IP
```

## Configuration

Command-line options:

```bash
sudo .venv/bin/python main.py --no-web
sudo .venv/bin/python main.py --no-dashboard
sudo .venv/bin/python main.py --web-host 127.0.0.1 --web-port 5000
sudo .venv/bin/python main.py --data-dir /var/lib/tcp-tarpit
```

The default trap ports and timing values are in `config.py`.

## Known Limitations

- Linux only.
- IPv4 TCP only.
- Do not run real services on the trap ports.
- SYN scans and connect scans behave differently depending on where the scanner runs.
- This is a lab project, not a replacement for a firewall or IDS.

## License

No license has been added yet.

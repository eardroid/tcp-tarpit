#!/usr/bin/env python3
import argparse
import logging
import os
import platform
import threading
from pathlib import Path

from netfilterqueue import NetfilterQueue

from config import DEFAULT_DATA_DIR, QUEUE_NUMBER, WEB_HOST, WEB_PORT
from dashboard import run_dashboard
from database import Database
from dribble import DribbleManager
from iptables import Iptables
from packet_handler import PacketHandler
from scanner_detector import ScannerDetector
from web_dashboard import WebDashboard


def parse_args():
    parser = argparse.ArgumentParser(description="Linux TCP tarpit")
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    parser.add_argument("--queue", type=int, default=QUEUE_NUMBER)
    parser.add_argument("--web-host", default=WEB_HOST)
    parser.add_argument("--web-port", type=int, default=WEB_PORT)
    parser.add_argument("--no-web", action="store_true")
    parser.add_argument("--no-dashboard", action="store_true")
    return parser.parse_args()


def set_up_logging(data_dir):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s level=%(levelname)s %(message)s",
        handlers=[logging.FileHandler(data_dir / "tarpit.log"), logging.StreamHandler()],
    )


def check_linux_root():
    if platform.system() != "Linux":
        raise SystemExit("This project is Linux-only. Run it on Ubuntu, Debian, Kali, or WSL2.")
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo so iptables, NFQUEUE, and Scapy raw packets can work.")


def main():
    args = parse_args()
    check_linux_root()
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    set_up_logging(data_dir)
    logging.info("tcp-tarpit startup queue=%s", args.queue)

    database = Database(data_dir / "tarpit.db")
    detector = ScannerDetector()
    handler = None

    def mark_dribble_finished(connection_id):
        handler.dribble_finished(connection_id)

    dribbler = DribbleManager(
        lambda state, byte: handler.send_dribble_byte(state, byte),
        mark_dribble_finished,
    )
    handler = PacketHandler(database, detector, dribbler)
    rules = Iptables(args.queue)
    queue = NetfilterQueue()
    stop_event = threading.Event()
    web = None
    queue_thread = None

    try:
        rules.install()
        queue.bind(args.queue, handler.process_packet)
        queue_thread = threading.Thread(target=queue.run, name="nfqueue", daemon=True)
        queue_thread.start()
        if not args.no_web:
            web = WebDashboard(database, dribbler, args.web_host, args.web_port)
            web.start()
            logging.info("web dashboard started on http://%s:%s", args.web_host, args.web_port)

        if args.no_dashboard:
            while not stop_event.wait(1):
                pass
        else:
            run_dashboard(database, dribbler, stop_event)
    except KeyboardInterrupt:
        logging.info("shutdown requested by Ctrl+C")
    except Exception:
        logging.exception("tarpit stopped because of an error")
        raise
    finally:
        logging.info("stopping dribble threads")
        stop_event.set()
        dribbler.stop_all()
        try:
            queue.unbind()
        except Exception:
            logging.exception("could not unbind NFQUEUE")
        if queue_thread:
            queue_thread.join(timeout=2)
        if web:
            web.stop()
        try:
            rules.remove()
        except Exception:
            logging.exception("could not remove iptables rules")
        database.close()
        logging.info("tcp-tarpit shutdown complete")


if __name__ == "__main__":
    main()

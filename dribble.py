import logging
import threading

from config import DRIBBLE_INTERVAL


class DribbleThread(threading.Thread):
    def __init__(self, state, send_byte, finished):
        super().__init__(name=f"dribble-{state['id']}", daemon=True)
        self.state = state
        self.send_byte = send_byte
        self.finished = finished
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        banner = self.state["banner"]
        position = 0
        logging.info("dribble thread started for connection %s", self.state["id"])
        try:
            while not self.stop_event.wait(DRIBBLE_INTERVAL):
                self.send_byte(self.state, banner[position:position + 1])
                position = (position + 1) % len(banner)
        except Exception:
            logging.exception("dribble thread failed for connection %s", self.state["id"])
        finally:
            self.finished(self.state["id"])
            logging.info("dribble thread stopped for connection %s", self.state["id"])


class DribbleManager:
    def __init__(self, send_byte, finished):
        self.send_byte = send_byte
        self.finished = finished
        self.threads = {}
        self.lock = threading.Lock()

    def start(self, state):
        with self.lock:
            if state["id"] in self.threads:
                return
            worker = DribbleThread(state, self.send_byte, self._finished)
            self.threads[state["id"]] = worker
            worker.start()

    def _finished(self, connection_id):
        with self.lock:
            self.threads.pop(connection_id, None)
        self.finished(connection_id)

    def stop(self, connection_id):
        with self.lock:
            worker = self.threads.get(connection_id)
        if worker:
            worker.stop()
            worker.join(timeout=2)

    def active_count(self):
        with self.lock:
            return len(self.threads)

    def stop_all(self):
        with self.lock:
            workers = list(self.threads.values())
        for worker in workers:
            worker.stop()
        for worker in workers:
            worker.join(timeout=2)

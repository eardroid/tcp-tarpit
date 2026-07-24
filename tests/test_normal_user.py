import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import Database
from scanner_detector import ScannerDetector


with tempfile.TemporaryDirectory() as folder:
    db = Database(Path(folder) / "test.db")
    detector = ScannerDetector()
    result, ports = detector.check("192.0.2.10", 80, now=100)
    assert result == "normal"
    assert ports == 1
    db.add_connection("192.0.2.10", 80, 50123, 64, 64240, "Linux", result, "normal")
    assert db.get_stats()["normal_connections"] == 1
    db.close()

print("normal-user path passed")

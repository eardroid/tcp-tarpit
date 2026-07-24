import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import Database


with tempfile.TemporaryDirectory() as folder:
    db = Database(Path(folder) / "test.db")
    connection_id = db.add_connection(
        "198.51.100.12", 22, 45678, 64, 65535, "BSD", "scanner", "trapped"
    )
    db.set_status(connection_id, "released")
    row = db.get_recent_connections(1)[0]
    assert row["status"] == "released"
    assert db.get_stats()["scanner_connections"] == 1
    db.close()

print("database logging path passed")

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner_detector import ScannerDetector


detector = ScannerDetector()
source = "192.0.2.20"
assert detector.check(source, 21, now=100)[0] == "normal"
assert detector.check(source, 22, now=105)[0] == "normal"
result, ports = detector.check(source, 23, now=109)
assert result == "scanner"
assert ports == 3
assert detector.check(source, 25, now=121)[0] == "normal"
print("scanner detection path passed")

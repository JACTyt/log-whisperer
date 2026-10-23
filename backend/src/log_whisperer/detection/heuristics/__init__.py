from log_whisperer.config import Settings
from log_whisperer.detection.base import Detector
from log_whisperer.detection.geoip import GeoIP
from log_whisperer.detection.heuristics.brute_force import BruteForceDetector
from log_whisperer.detection.heuristics.impossible_travel import ImpossibleTravelDetector
from log_whisperer.detection.heuristics.new_admin_user import NewAdminUserDetector
from log_whisperer.detection.heuristics.suspicious_powershell import SuspiciousPowerShellDetector

_geoip_cache: dict[str, GeoIP | None] = {}


def _geoip(settings: Settings) -> GeoIP | None:
    key = str(settings.geoip.path)
    if key not in _geoip_cache:
        _geoip_cache[key] = GeoIP.open(settings.geoip.path)
    return _geoip_cache[key]


def default_detectors(settings: Settings) -> list[Detector]:
    d = settings.detection
    return [
        BruteForceDetector(d.brute_force_threshold, d.brute_force_window_min, d.brute_force_success_window_min),
        ImpossibleTravelDetector(_geoip(settings), d.impossible_travel_kmh),
        NewAdminUserDetector(d.admin_groups, d.new_admin_window_min),
        SuspiciousPowerShellDetector(),
    ]

"""Many failed authentications in a short window, optionally followed by a success."""

from collections import defaultdict
from datetime import timedelta

from log_whisperer.detection.heuristics.common import candidates, has_new, make_detection
from log_whisperer.models import Detection, Event
from log_whisperer.store import Store

AUTH_ACTIONS = ("logon", "ssh_auth", "kerberos_preauth", "credential_validation", "explicit_logon")


class BruteForceDetector:
    rule_id = "heuristic.brute_force"
    title = "Brute-force authentication"

    def __init__(self, threshold: int = 10, window_min: int = 5, success_window_min: int = 30):
        self.threshold = threshold
        self.window = timedelta(minutes=window_min)
        self.success_window = timedelta(minutes=success_window_min)

    def _bursts(self, failures: list[Event]) -> list[list[Event]]:
        """Split into bursts (gap <= window); keep those with >= threshold events inside one window."""
        bursts, current = [], []
        for e in failures:
            if current and e.ts - current[-1].ts > self.window:
                bursts.append(current)
                current = []
            current.append(e)
        if current:
            bursts.append(current)
        out = []
        for b in bursts:
            j = 0
            for i in range(len(b)):
                while b[i].ts - b[j].ts > self.window:
                    j += 1
                if i - j + 1 >= self.threshold:
                    out.append(b)
                    break
        return out

    def run(self, store: Store, since_seq: int | None = None) -> list[Detection]:
        placeholders = ", ".join("?" for _ in AUTH_ACTIONS)
        events = candidates(store, f"action IN ({placeholders}) AND outcome IS NOT NULL",
                            list(AUTH_ACTIONS), since_seq, self.window + self.success_window)
        failures = [e for e in events if e.outcome == "failure"]
        successes = [e for e in events if e.outcome == "success"]

        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in failures:
            if e.src_ip:
                groups[("src_ip", e.src_ip)].append(e)
        covered: set[str] = set()
        detections = []
        for key in sorted(groups):
            detections += self._detect(key, groups[key], successes, since_seq, covered)
        # Per-target-user pass catches IP rotation; skip failures already explained by an IP burst.
        by_user: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in failures:
            if e.user and e.event_id not in covered:
                by_user[("user", f"{e.host}|{e.user}")].append(e)
        for key in sorted(by_user):
            detections += self._detect(key, by_user[key], successes, since_seq, covered)
        return detections

    def _detect(self, key, failures, successes, since_seq, covered) -> list[Detection]:
        kind, value = key
        out = []
        for burst in self._bursts(failures):
            end = burst[-1].ts
            follow = next((s for s in successes
                           if burst[0].ts <= s.ts <= end + self.success_window
                           and ((kind == "src_ip" and s.src_ip == value)
                                or (kind == "user" and f"{s.host}|{s.user}" == value))), None)
            events = burst + ([follow] if follow else [])
            if not has_new(events, since_seq):
                continue
            covered.update(e.event_id for e in burst)
            out.append(make_detection(
                self.rule_id,
                f"{self.title} from {value}" if kind == "src_ip" else f"{self.title} against {value.split('|')[1]}",
                "high" if follow else "medium",
                ["T1110.001", "T1078"] if follow else ["T1110.001"],
                events, key=f"{kind}:{value}",
            ))
        return out

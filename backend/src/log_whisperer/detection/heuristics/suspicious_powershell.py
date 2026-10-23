"""PowerShell with encoded commands, download cradles, AMSI bypasses or hidden windows."""

import re
from datetime import timedelta

from log_whisperer.detection.heuristics.common import candidates, make_detection
from log_whisperer.models import Detection, Event
from log_whisperer.store import Store

# class -> (pattern, extra techniques)
PATTERNS: dict[str, tuple[re.Pattern, list[str]]] = {
    "encoded": (re.compile(r"\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{12,}|frombase64string", re.I), ["T1027"]),
    "iex": (re.compile(r"\biex\b|invoke-expression", re.I), []),
    "download": (re.compile(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer", re.I),
                 ["T1105"]),
    "amsi": (re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I), ["T1562.001"]),
    "hidden": (re.compile(r"\s-w(indowstyle)?\s+h(idden)?\b", re.I), ["T1564.003"]),
    "noprofile": (re.compile(r"\s-nop(rofile)?\b", re.I), []),
}
WEAK = {"noprofile", "hidden"}  # not suspicious on their own


def classify(text: str) -> list[str]:
    return [name for name, (rx, _) in PATTERNS.items() if rx.search(text)]


class SuspiciousPowerShellDetector:
    rule_id = "heuristic.suspicious_powershell"
    title = "Suspicious PowerShell"

    def run(self, store: Store, since_seq: int | None = None) -> list[Detection]:
        where = ("command_line IS NOT NULL AND (action = 'script_block' OR (action = 'process_start' AND "
                 "(process ILIKE '%powershell%' OR process ILIKE '%pwsh%' OR command_line ILIKE '%powershell%')))")
        events: list[Event] = candidates(store, where, [], since_seq, timedelta(0))
        out = []
        for e in events:
            if since_seq is not None and (e.seq or 0) <= since_seq:
                continue
            classes = classify(e.command_line)
            strong = [c for c in classes if c not in WEAK]
            if not strong:
                continue
            techniques = ["T1059.001"] + [t for c in classes for t in PATTERNS[c][1]]
            out.append(make_detection(
                self.rule_id, f"{self.title} ({', '.join(classes)})",
                "high" if len(classes) >= 2 else "medium",
                list(dict.fromkeys(techniques)), [e],
            ))
        return out

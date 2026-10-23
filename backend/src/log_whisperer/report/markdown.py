"""Incident report as Markdown; every narrative claim carries footnote citations to raw log lines."""

from collections.abc import Mapping, Sequence

from log_whisperer.attack.table import AttackRow
from log_whisperer.models import Detection, Event, Incident
from log_whisperer.narrative.schema import StoredNarrative
from log_whisperer.response.actions import ADVISORY, SuggestedAction

MAX_CITES = 3
RAW_CHARS = 400


def cell(text: object) -> str:
    """Make arbitrary (attacker-controlled) text safe inside a Markdown table cell."""
    s = " ".join(str(text).split())
    for a, b in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("`", "\\`"), ("[", "\\["),
                 ("*", "\\*"), ("_", "\\_")):
        s = s.replace(a, b)
    return s


def code_span(text: str) -> str:
    """Inline code that survives backticks in the content (fence longer than any inner run)."""
    s = " ".join(text.split())
    longest = cur = 0
    for ch in s:
        cur = cur + 1 if ch == "`" else 0
        longest = max(longest, cur)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


class _Citations:
    def __init__(self) -> None:
        self.order: dict[str, int] = {}

    def cite(self, event_ids: Sequence[str]) -> str:
        refs = []
        for eid in event_ids[:MAX_CITES]:
            n = self.order.setdefault(eid, len(self.order) + 1)
            refs.append(f"[^e{n}]")
        extra = f" (+{len(event_ids) - MAX_CITES} more)" if len(event_ids) > MAX_CITES else ""
        return "".join(refs) + extra


def render_markdown(incident: Incident, detections: Sequence[Detection], narrative: StoredNarrative | None,
                    attack_rows: Sequence[AttackRow], actions: Sequence[SuggestedAction] | None,
                    events_by_id: Mapping[str, Event]) -> str:
    c = _Citations()
    nv = narrative.narrative if narrative else None
    out = [
        f"# Incident report: {cell(incident.title)}", "",
        "| | |", "|---|---|",
        f"| Incident | `{incident.incident_id}` |",
        f"| Time (UTC) | {incident.ts_start:%Y-%m-%d %H:%M:%S} – {incident.ts_end:%Y-%m-%d %H:%M:%S} |",
        f"| Severity | **{incident.severity}** |",
        f"| Hosts | {cell(', '.join(incident.hosts) or '-')} |",
        f"| Users | {cell(', '.join(incident.users) or '-')} |",
        f"| Source IPs | {cell(', '.join(incident.src_ips) or '-')} |",
        f"| Narrative | {cell(narrative.model) + ' at ' + f'{narrative.created_at:%Y-%m-%d %H:%M}' if narrative else 'no narrative generated'} |",
        "",
    ]

    out += ["## Summary", ""]
    if nv and nv.summary:
        note = " _(template summary: the model's summary failed validation)_" if nv.summary_is_template else ""
        out += [f"{cell(nv.summary.text)} {c.cite(nv.summary.event_ids)}{note}", ""]
    else:
        out += ["No narrative generated — the timeline below lists detections only.", ""]

    out += ["## Timeline", "", "| Time (UTC) | What happened | ATT&CK | Evidence |", "|---|---|---|---|"]
    if nv and nv.steps:
        for s in nv.steps:
            out.append(f"| {s.ts:%H:%M:%S} | {cell(s.text)} | {', '.join(s.techniques) or '-'} | {c.cite(s.event_ids)} |")
    else:
        for d in detections:
            out.append(f"| {d.ts_first:%H:%M:%S} | Detection: {cell(d.rule_title)} | {', '.join(d.techniques) or '-'} "
                       f"| {c.cite(d.event_ids)} |")
    out.append("")

    out += ["## Detections", "", "| First seen | Rule | Source | Severity | Events |", "|---|---|---|---|---|"]
    for d in detections:
        out.append(f"| {d.ts_first:%H:%M:%S} | {cell(d.rule_title)} | {d.rule_source} | {d.severity} | {len(d.event_ids)} |")
    out.append("")

    if attack_rows:
        out += ["## MITRE ATT&CK", "", "| Tactic | Technique | Name |", "|---|---|---|"]
        out += [f"| {r.tactic} | [{r.technique_id}]({r.url}) | {cell(r.name)} |" for r in attack_rows]
        out.append("")

    if actions:
        out += ["## Suggested response actions", "", f"_{ADVISORY}_", ""]
        out += [f"{i}. **[{a.priority.replace('_', ' ')}]** {cell(a.action)} — {cell(a.rationale)} {c.cite(a.event_ids)}"
                for i, a in enumerate(actions, 1)]
        out.append("")

    if nv and nv.rejected:
        out += ["## Dropped by the citation validator", "",
                "These model statements were not shown as fact because they failed validation:", ""]
        out += [f"- `{r.reason}` — {cell(r.text)}" for r in nv.rejected]
        out.append("")

    if c.order:
        out += ["## Evidence", ""]
        for eid, n in c.order.items():
            e = events_by_id.get(eid)
            if e is None:
                out.append(f"[^e{n}]: event `{eid}` (not in incident context)")
                continue
            raw = e.raw if len(e.raw) <= RAW_CHARS else e.raw[:RAW_CHARS] + "…"
            out.append(f"[^e{n}]: {e.ts:%Y-%m-%d %H:%M:%S} · {e.source_type} · "
                       f"{cell(e.source_file.replace(chr(92), '/').rsplit('/', 1)[-1])} {e.record_ref} · "
                       f"{code_span(raw)}")
        out.append("")
    return "\n".join(out)

"""A user account created and then added to an administrative group shortly after."""

from datetime import timedelta

from log_whisperer.detection.heuristics.common import candidates, has_new, make_detection
from log_whisperer.models import Detection, Event
from log_whisperer.store import Store


def _group(e: Event) -> str | None:
    g = e.fields.get("group") if e.source_type == "authlog" else e.fields.get("TargetUserName")
    return str(g).lower() if g else None


def _keys(e: Event) -> set[tuple]:
    """Identities for joining a creation with a group add: (host, user) and Windows SIDs."""
    keys = {(e.host, "user", e.user)} if e.user else set()
    sid = e.fields.get("TargetSid" if e.action == "user_created" else "MemberSid")
    if sid and sid != "-":
        keys.add((e.host, "sid", sid))
    return keys


class NewAdminUserDetector:
    rule_id = "heuristic.new_admin_user"
    title = "New user added to admin group"

    def __init__(self, admin_groups: list[str], window_min: int = 60):
        self.admin_groups = {g.lower() for g in admin_groups}
        self.window = timedelta(minutes=window_min)

    def run(self, store: Store, since_seq: int | None = None) -> list[Detection]:
        events = candidates(store, "action IN ('user_created', 'group_member_added')", [], since_seq, self.window)
        created = [e for e in events if e.action == "user_created"]
        added = [e for e in events if e.action == "group_member_added" and _group(e) in self.admin_groups]
        out, matched = [], set()
        for add in added:
            for c in created:
                if c.event_id in matched:
                    continue
                if c.ts <= add.ts <= c.ts + self.window and _keys(c) & _keys(add) and has_new([c, add], since_seq):
                    matched.add(c.event_id)
                    name = c.user or add.user or "?"
                    out.append(make_detection(
                        self.rule_id, f"{self.title}: {name} → {_group(add)}", "high",
                        ["T1136.001", "T1098"], [c, add], key=name,
                    ))
                    break
        return out

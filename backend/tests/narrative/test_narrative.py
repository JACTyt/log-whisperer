from datetime import timedelta
from pathlib import Path

import pytest

from log_whisperer.attack import default_catalog
from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import ingest_path
from log_whisperer.llm.base import LLMError
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.narrative.prompt import render_context
from log_whisperer.narrative.service import NarrativeError, generate_narrative, load_incident_bundle
from log_whisperer.narrative.validator import validate
from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.store import Store

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path_factory.mktemp("g") / "none.mmdb"
    store = Store(":memory:")
    ingest_path(store, FIX / "auth.log", [], force=AuthLogParser(year=2026))
    run_all(store, s)
    [inc] = rebuild_incidents(store, s)
    yield store, s, inc
    store.close()


@pytest.fixture(scope="module")
def ctx(env):
    store, _, inc = env
    bundle = load_incident_bundle(store, inc.incident_id)
    return bundle, render_context(bundle.incident, bundle.events, bundle.detections)


def alias_for(ctx, predicate):
    bundle, rc = ctx
    for alias, ids in rc.alias_to_ids.items():
        if any(predicate(bundle.events_by_id[i]) for i in ids):
            return alias
    raise AssertionError("no alias")


def test_render_collapses_failure_run(ctx):
    bundle, rc = ctx
    collapsed = [a for a, ids in rc.alias_to_ids.items() if len(ids) > 3]
    assert collapsed, rc.text
    assert "(x" in rc.text and "DETECTION" in rc.text
    assert set(i for ids in rc.alias_to_ids.values() for i in ids) == set(bundle.incident.context_event_ids)


def test_render_respects_budget(ctx):
    bundle, full = ctx
    small = render_context(bundle.incident, bundle.events, bundle.detections, max_chars=1500)
    assert len(small.alias_to_ids) < len(full.alias_to_ids)  # non-detection lines trimmed
    det_events = {e for d in bundle.detections for e in d.event_ids}
    assert det_events <= {i for ids in small.alias_to_ids.values() for i in ids}


def _good(ctx):
    bundle, rc = ctx
    fail = max(rc.alias_to_ids, key=lambda a: len(rc.alias_to_ids[a]))
    ok = alias_for(ctx, lambda e: e.action == "ssh_auth" and e.outcome == "success" and e.user == "root")
    add = alias_for(ctx, lambda e: e.action == "group_member_added")
    return {
        "summary": {"text": "An attacker from 203.0.113.7 brute-forced SSH on web01 and created a sudo user.",
                    "event_ids": [fail, ok, add]},
        "steps": [
            {"ts": rc.alias_ts[fail][0].strftime("%Y-%m-%dT%H:%M:%SZ"),
             "text": "203.0.113.7 keeps guessing the root password over SSH.",
             "event_ids": [fail], "techniques": ["T1110.001"]},
            {"ts": "2026-03-14T14:09:12Z", "text": "The attacker logs in as root from 203.0.113.7.",
             "event_ids": [ok], "techniques": ["T1078"]},
            {"ts": "2026-03-14T14:11:31Z", "text": "User backdoor is added to the sudo group.",
             "event_ids": [add], "techniques": ["T1098"]},
        ],
    }


def _validate(ctx, raw):
    bundle, rc = ctx
    return validate(raw, rc, bundle.events_by_id, default_catalog(), bundle.known_entities)


def test_valid_narrative_passes_and_expands_aliases(ctx):
    nv = _validate(ctx, _good(ctx))
    assert len(nv.steps) == 3 and nv.rejected == [] and nv.summary is not None
    assert len(nv.steps[0].event_ids) > 3  # collapsed run expands to all its events
    assert all(not i.startswith("E") or len(i) == 16 for s in nv.steps for i in s.event_ids)


def test_unknown_citation_rejected(ctx):
    raw = _good(ctx)
    raw["steps"][1]["event_ids"] = ["E999"]
    nv = _validate(ctx, raw)
    assert len(nv.steps) == 2 and nv.rejected[0].reason == "unknown_citation:E999"


def test_uncited_step_rejected(ctx):
    raw = _good(ctx)
    raw["steps"][0]["event_ids"] = []
    assert _validate(ctx, raw).rejected[0].reason == "no_citation"


def test_ungrounded_ip_rejected(ctx):
    raw = _good(ctx)
    raw["steps"][2]["text"] = "User backdoor, controlled from 198.51.100.66, is added to sudo."
    nv = _validate(ctx, raw)
    assert nv.rejected[0].reason == "ungrounded_entity:198.51.100.66"


def test_ungrounded_known_user_rejected(ctx):
    raw = _good(ctx)
    raw["steps"][2]["text"] = "User root is added to the sudo group."
    assert _validate(ctx, raw).rejected[0].reason == "ungrounded_entity:root"


def test_timestamp_out_of_range_rejected(ctx):
    raw = _good(ctx)
    raw["steps"][1]["ts"] = "2026-03-14T18:00:00Z"
    assert _validate(ctx, raw).rejected[0].reason == "timestamp_mismatch"


def test_unknown_technique_stripped_not_fatal(ctx):
    raw = _good(ctx)
    raw["steps"][0]["techniques"] = ["T1110.001", "T9999"]
    nv = _validate(ctx, raw)
    assert nv.steps[0].techniques == ["T1110.001"]
    assert nv.rejected[0].reason == "unknown_technique:T9999" and len(nv.steps) == 3


def test_alias_formats_tolerated(ctx):
    raw = _good(ctx)
    raw["steps"][1]["event_ids"] = [f"[{raw['steps'][1]['event_ids'][0].lower()}]"]
    assert len(_validate(ctx, raw).steps) == 3


def test_bad_summary_dropped(ctx):
    raw = _good(ctx)
    raw["summary"]["event_ids"] = []
    nv = _validate(ctx, raw)
    assert nv.summary is None and nv.rejected[0].index == -1


# -- service --------------------------------------------------------------------

def test_generate_persists(env, ctx):
    store, s, inc = env
    nv = generate_narrative(store, inc.incident_id, FakeProvider([_good(ctx)]), s)
    assert len(nv.steps) == 3
    stored = store.latest_narrative(inc.incident_id)
    assert stored.model == "fake:fake-model" and stored.narrative == nv


def test_retry_on_invalid_json(env, ctx):
    store, s, inc = env
    fake = FakeProvider([LLMError("invalid JSON"), _good(ctx)])
    assert len(generate_narrative(store, inc.incident_id, fake, s).steps) == 3
    assert len(fake.calls) == 2


def test_twice_invalid_raises(env):
    store, s, inc = env
    with pytest.raises(NarrativeError):
        generate_narrative(store, inc.incident_id, FakeProvider([LLMError("x"), LLMError("y")]), s)


def test_schema_mismatch_counts_as_invalid(env, ctx):
    store, s, inc = env
    fake = FakeProvider([{"steps": "nope"}, _good(ctx)])
    assert len(generate_narrative(store, inc.incident_id, fake, s).steps) == 3


def test_bad_summary_replaced_by_template(env, ctx):
    store, s, inc = env
    raw = _good(ctx)
    raw["summary"] = {"text": "Something happened.", "event_ids": []}
    nv = generate_narrative(store, inc.incident_id, FakeProvider([raw]), s)
    assert nv.summary is not None and nv.summary.event_ids and nv.summary_is_template


def test_prompt_marks_logs_as_untrusted(env, ctx):
    store, s, inc = env
    fake = FakeProvider([_good(ctx)])
    generate_narrative(store, inc.incident_id, fake, s)
    system = fake.calls[0][1]["system"]
    assert "untrusted" in system.lower() and "cite" in system.lower()


def test_unknown_incident(env):
    store, s, _ = env
    with pytest.raises(KeyError):
        generate_narrative(store, "nope", FakeProvider([]), s)


def test_step_times_are_utc_naive(env, ctx):
    nv = _validate(ctx, _good(ctx))
    assert nv.steps[1].ts.tzinfo is None
    assert nv.steps[2].ts - nv.steps[1].ts == timedelta(minutes=2, seconds=19)

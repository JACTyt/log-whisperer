import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from log_whisperer.api.app import create_app
from log_whisperer.api.routes.actions import safe_filename
from log_whisperer.config import Settings
from log_whisperer.llm import ProviderUnavailable
from log_whisperer.llm.base import ChatTurn
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.store import Store

FIX = Path(__file__).parents[1] / "fixtures"


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path / "none.mmdb"
    s.storage.upload_dir = tmp_path / "uploads"
    return s


@pytest.fixture
def fake():
    return FakeProvider()


@pytest.fixture
def client(settings, fake):
    store = Store(":memory:")
    app = create_app(settings, store, provider_factory=lambda s, p, m: fake)
    with TestClient(app) as c:
        yield c
    store.close()


def wait(client, job_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.05)
    raise AssertionError("job timeout")


def upload(client, *names):
    files = [("files", (n, (FIX / n).read_bytes())) for n in names]
    r = client.post("/api/ingest", files=files)
    assert r.status_code == 202
    return wait(client, r.json()["id"])


def test_health_and_providers(client, monkeypatch):
    from log_whisperer.api.routes import data

    monkeypatch.setattr(data, "installed_ollama_models",
                        lambda: ["ssfdre38/gemma4-turbo:e4b", "nomic-embed-text:latest", "gemma4:26b-a4b"])
    assert client.get("/api/health").json() == {"status": "ok", "events": 0}
    p = client.get("/api/providers").json()
    assert (p["default"], p["default_model"]) == ("ollama", "gemma4:26b-a4b")
    models = {(m["provider"], m["model"]): m["installed"] for m in p["models"]}
    assert models[("ollama", "gemma4:26b-a4b")] is True
    assert models[("ollama", "gemma4:e4b")] is False  # official 4B tag offered even before it is pulled
    assert models[("ollama", "ssfdre38/gemma4-turbo:e4b")] is True
    assert ("ollama", "nomic-embed-text:latest") not in models  # embedding models can't chat
    assert ("anthropic", "claude-opus-5-5") in models
    assert not any(m["provider"] == "openai" for m in p["models"])  # no openai_model configured


def test_providers_when_ollama_down(client, monkeypatch):
    from log_whisperer.api.routes import data

    monkeypatch.setattr(data, "installed_ollama_models", lambda: None)
    p = client.get("/api/providers").json()
    assert p["ollama_reachable"] is False
    assert {m["model"] for m in p["models"] if m["provider"] == "ollama"} == {"gemma4:26b-a4b", "gemma4:e4b"}


def test_upload_detect_and_read(client):
    job = upload(client, "access.log", "winjson_flat.jsonl")
    assert job["status"] == "done", job
    assert job["result"]["inserted"] == 14 and job["result"]["incidents"] >= 1
    events = client.get("/api/events", params={"source_type": "web", "limit": 5}).json()
    assert events["total"] == 11 and len(events["items"]) == 5
    assert client.get("/api/events", params={"q": "UNION%20SELECT"}).json()["total"] == 1
    assert client.get("/api/events", params={"q": "' OR 1=1; --"}).json()["total"] == 0
    incidents = client.get("/api/incidents").json()
    detail = client.get(f"/api/incidents/{incidents[0]['incident_id']}").json()
    assert detail["detections"] and detail["events"] and detail["attack"] is not None
    assert detail["narrative"] is None
    first = events["items"][0]["event_id"]
    assert client.get(f"/api/events/{first}").json()["event_id"] == first


def test_incident_sources_name_the_files(client):
    upload(client, "auth.log", "access.log")
    incidents = client.get("/api/incidents").json()
    big = next(i for i in incidents if "203.0.113.7" in i["src_ips"])
    assert {p.replace("\\", "/").rsplit("/", 1)[-1] for p in big["source_files"]} == {"auth.log", "access.log"}
    detail = client.get(f"/api/incidents/{big['incident_id']}").json()
    sources = {s["name"]: s for s in detail["sources"]}
    assert sources["auth.log"]["source_type"] == "authlog" and sources["auth.log"]["kind"] == "Linux auth log"
    assert sources["access.log"]["kind"] == "Web server access log"
    assert sum(s["events"] for s in detail["sources"]) == len(detail["events"])
    assert len(sources["auth.log"]["event_ids"]) == sources["auth.log"]["events"]
    # the stored path is the upload copy; the displayed name is the original file name
    assert sources["auth.log"]["source_file"].endswith("auth.log")


def test_full_log_per_file(client):
    upload(client, "auth.log", "access.log")
    files = {f["name"]: f for f in client.get("/api/sources").json()}
    auth = files["auth.log"]
    assert auth["events"] == 31 and auth["kind"] == "Linux auth log"
    incidents = client.get("/api/incidents").json()
    for f in files.values():
        assert f["incidents"] == sum(1 for i in incidents if f["source_file"] in i["source_files"])
    assert files["access.log"]["incidents"] >= 1

    page = client.get("/api/events", params={"source_file": auth["source_file"], "order": "file", "limit": 10}).json()
    assert page["total"] == 31
    lines = [e["record_ref"] for e in page["items"]]
    assert lines == [f"line:{n}" for n in range(1, 11)]  # original file order
    # lines that belong to an incident say which one
    in_incident = [e["event_id"] for e in page["items"] if page["incidents"].get(e["event_id"])]
    assert in_incident and all(len(page["incidents"][i]) == 1 for i in in_incident)


def test_full_log_focus_jumps_to_line(client):
    upload(client, "auth.log")
    auth = client.get("/api/sources").json()[0]
    all_lines = client.get("/api/events", params={"source_file": auth["source_file"], "order": "file",
                                                  "limit": 500}).json()["items"]
    target = all_lines[24]  # line 25
    page = client.get("/api/events", params={"source_file": auth["source_file"], "order": "file", "limit": 10,
                                             "focus": target["event_id"]}).json()
    assert page["offset"] == 20 and target["event_id"] in [e["event_id"] for e in page["items"]]


def test_line_shared_by_two_incidents(client, settings):
    from log_whisperer.detection.runner import run_all
    from log_whisperer.incidents.service import rebuild_incidents
    from tests.helpers import ev, failures

    store = client.app.state.store
    # two brute-force bursts on the same host 45 min apart (gap > 30 min -> two incidents),
    # and an ordinary line in between that both incidents keep as context
    store.insert_events(failures(12, start=0, src_ip="203.0.113.7", user="root"))
    between = ev(25, action="sudo", user="deploy", raw="sudo: deploy : COMMAND=/usr/bin/apt update")
    store.insert_events([between])
    store.insert_events(failures(12, start=45, src_ip="198.51.100.9", user="root"))
    run_all(store, settings)
    first, second = rebuild_incidents(store, settings)
    assert between.event_id in first.context_event_ids and between.event_id in second.context_event_ids

    detail = client.get(f"/api/incidents/{first.incident_id}").json()
    assert detail["shared"][between.event_id] == [second.incident_id]
    assert all(second.incident_id not in v or k in second.context_event_ids for k, v in detail["shared"].items())
    page = client.get("/api/events", params={"limit": 500}).json()
    assert sorted(page["incidents"][between.event_id]) == sorted([first.incident_id, second.incident_id])


def test_404s(client):
    assert client.get("/api/events/nope").status_code == 404
    assert client.get("/api/incidents/nope").status_code == 404
    assert client.get("/api/jobs/nope").status_code == 404
    assert client.post("/api/incidents/nope/narrative").status_code == 404


def test_upload_size_limit(client, settings):
    settings.api.max_upload_mb = 0
    r = client.post("/api/ingest", files=[("files", ("a.log", b"x" * 10))])
    assert r.status_code == 413


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("..\\..\\win.ini") == "win.ini"
    assert safe_filename("...") == "upload" and safe_filename(None) == "upload"
    assert safe_filename("a b;c.evtx") == "a_b_c.evtx"


def test_sse_stream(client):
    r = client.post("/api/detect")
    job_id = r.json()["id"]
    with client.stream("GET", f"/api/jobs/{job_id}/stream") as s:
        body = "".join(s.iter_text())
    assert "event: done" in body or "event: error" in body


def test_narrative_job_and_unavailable_provider(client, fake, settings):
    upload(client, "auth.log")
    inc = client.get("/api/incidents").json()[0]
    fake.json_responses.append({"summary": {"text": "s", "event_ids": []}, "steps": []})
    job = wait(client, client.post(f"/api/incidents/{inc['incident_id']}/narrative").json()["id"])
    assert job["status"] == "done", job
    n = client.get(f"/api/incidents/{inc['incident_id']}/narrative").json()
    assert n["narrative"]["summary_is_template"] is True and n["model"] == "fake:fake-model"

    def unavailable(s, p, m):
        raise ProviderUnavailable("Ollama not reachable")

    client.app.state.provider_factory = unavailable
    r = client.post(f"/api/incidents/{inc['incident_id']}/narrative")
    assert r.status_code == 503 and "Ollama" in r.json()["detail"]


def test_report_and_actions_routes(client, fake):
    upload(client, "auth.log")
    inc = client.get("/api/incidents").json()[0]["incident_id"]
    md = client.get(f"/api/incidents/{inc}/report")
    assert md.status_code == 200 and md.text.startswith("# Incident report")
    assert client.get(f"/api/incidents/{inc}/report", params={"format": "pdf"}).status_code in (200, 501)
    fake.json_responses.append({"actions": []})
    job = wait(client, client.post(f"/api/incidents/{inc}/actions").json()["id"])
    assert job["status"] == "done" and job["result"]["actions"] == []
    fake.json_responses.append({"yaml": "title: [", "explanation": "", "event_ids": ["E1"]})
    job = wait(client, client.post(f"/api/incidents/{inc}/rule-drafts").json()["id"])
    assert job["result"]["status"] == "rejected"


def test_live_start_stop(client, settings):
    settings.live.syslog_port = 0
    assert client.get("/api/live/status").json()["running"] is False
    started = client.post("/api/live/start").json()
    assert started["running"] is True and started["syslog_port"] > 0
    assert client.post("/api/live/stop").json()["running"] is False


def test_chat_session(client, fake):
    upload(client, "auth.log")
    inc = client.get("/api/incidents").json()[0]
    fake.chat_turns += [ChatTurn(content='{"answer": [{"text": "Nothing.", "event_ids": [], "no_data": true}]}'),
                        ChatTurn(content='not json')]
    r = client.post("/api/chat", json={"message": "hi", "incident_id": inc["incident_id"]}).json()
    assert r["no_data"] == ["Nothing."] and r["session_id"]
    r2 = client.post("/api/chat", json={"message": "again", "session_id": r["session_id"]})
    assert r2.status_code == 502
    assert client.post("/api/chat", json={"message": "x", "incident_id": "nope"}).status_code == 404

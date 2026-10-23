"""`logw` command-line interface."""

import logging
from pathlib import Path
from typing import Annotated

import typer

from log_whisperer.config import Settings, load_settings
from log_whisperer.ingest import IngestResult, ingest_path
from log_whisperer.parsers import default_parsers, parser_by_type
from log_whisperer.store import Store

app = typer.Typer(no_args_is_help=True, help="Log Whisperer: raw logs to cited attack timelines.")
rules_app = typer.Typer(no_args_is_help=True, help="Manage Sigma rules.")
app.add_typer(rules_app, name="rules")

DbOpt = Annotated[Path | None, typer.Option(help="DuckDB file (default from config).")]


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    """Log Whisperer CLI."""
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")


def _settings() -> Settings:
    return load_settings()


def _db_path(db: Path | None) -> Path:
    return db or _settings().storage.db_path


@app.command()
def ingest(
    paths: Annotated[list[Path], typer.Argument(help="Log files or directories.")],
    db: Annotated[Path | None, typer.Option(help="DuckDB file (default from config).")] = None,
    type: Annotated[str | None, typer.Option("--type", help="Force a parser: evtx|winjson|web|authlog.")] = None,
) -> None:
    """Parse log files and store normalized events."""
    total = IngestResult()
    parsers = default_parsers()
    force = parser_by_type(type) if type else None
    with Store(_db_path(db)) as store:
        for path in paths:
            total.add(ingest_path(store, path, parsers, force=force))
    for err in total.errors:
        typer.echo(f"error: {err}", err=True)
    typer.echo(
        f"files={total.files} parsed={total.parsed} inserted={total.inserted} "
        f"skipped_lines={total.skipped_lines} errors={len(total.errors)}"
    )
    if total.files == 0 and total.errors:
        raise typer.Exit(1)


@app.command()
def detect(
    db: DbOpt = None,
    since_seq: Annotated[int | None, typer.Option(help="Only events with seq > N.")] = None,
    rules: Annotated[list[Path] | None, typer.Option(help="Rule directories (default from config).")] = None,
) -> None:
    """Run Sigma rules and heuristics, store detections, rebuild incidents."""
    from log_whisperer.detection.runner import run_all
    from log_whisperer.incidents.service import rebuild_incidents

    settings = _settings()
    if rules:
        settings.detection.sigma_dirs = rules
    with Store(_db_path(db)) as store:
        r = run_all(store, settings, since_seq=since_seq)
        incidents = rebuild_incidents(store, settings)
    for title, n in sorted(r.by_rule.items(), key=lambda kv: -kv[1]):
        typer.echo(f"{n:6d}  {title}")
    typer.echo(f"rules={r.rule_report.loaded} unsupported={len(r.rule_report.unsupported)} "
               f"query_errors={len(r.errors)} new_detections={r.detections_new} incidents={len(incidents)}")


@app.command()
def incidents(
    db: DbOpt = None,
    min_severity: Annotated[str, typer.Option(help="Hide incidents below this severity.")] = "low",
) -> None:
    """List incidents."""
    from log_whisperer.models import severity_rank

    with Store(_db_path(db)) as store:
        rows = [i for i in store.list_incidents() if severity_rank(i.severity) >= severity_rank(min_severity)]
    for i in rows:
        typer.echo(f"{i.incident_id}  {i.ts_start:%Y-%m-%d %H:%M}–{i.ts_end:%H:%M}  {i.severity:<8} "
                   f"{i.title[:60]:<60}  hosts={','.join(i.hosts[:3])} users={','.join(i.users[:3])} "
                   f"events={len(i.context_event_ids)} [{' '.join(i.techniques[:4])}]")
    typer.echo(f"{len(rows)} incidents")


ProviderOpt = Annotated[str | None, typer.Option(help="ollama | anthropic | openai (default from config).")]
ModelOpt = Annotated[str | None, typer.Option(help="Model name for the provider.")]


def _provider(settings: Settings, provider: str | None, model: str | None):
    from log_whisperer.llm import ProviderUnavailable, get_provider

    try:
        return get_provider(settings, provider, model)
    except ProviderUnavailable as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


@app.command()
def narrate(
    incident_id: str,
    db: DbOpt = None,
    provider: ProviderOpt = None,
    model: ModelOpt = None,
) -> None:
    """Generate a cited attack narrative for an incident."""
    from log_whisperer.llm import LLMError
    from log_whisperer.narrative.service import NarrativeError, generate_narrative

    settings = _settings()
    llm = _provider(settings, provider, model)
    with Store(_db_path(db)) as store:
        try:
            nv = generate_narrative(store, incident_id, llm, settings)
        except KeyError as exc:
            typer.echo(f"error: {exc.args[0]}", err=True)
            raise typer.Exit(1) from exc
        except (NarrativeError, LLMError) as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from exc
    typer.echo(f"SUMMARY{' (template)' if nv.summary_is_template else ''}: {nv.summary.text}")
    typer.echo(f"         cites {len(nv.summary.event_ids)} events\n")
    for s in nv.steps:
        typer.echo(f"{s.ts:%Y-%m-%d %H:%M:%S}  {s.text}  [{', '.join(s.techniques)}]")
        typer.echo(f"                     cites: {', '.join(s.event_ids[:4])}"
                   f"{f' (+{len(s.event_ids) - 4})' if len(s.event_ids) > 4 else ''}")
    if nv.rejected:
        typer.echo(f"\n{len(nv.rejected)} item(s) dropped by the citation validator:")
        for r in nv.rejected:
            typer.echo(f"  - [{r.reason}] {r.text[:100]}")


@app.command()
def chat(
    incident_id: Annotated[str | None, typer.Argument(help="Incident to focus on (omit with --global).")] = None,
    global_: Annotated[bool, typer.Option("--global", help="Search all data, not one incident.")] = False,
    db: DbOpt = None,
    provider: ProviderOpt = None,
    model: ModelOpt = None,
) -> None:
    """Ask questions about an incident or all data; answers cite log events."""
    from log_whisperer.chat.service import ChatService
    from log_whisperer.chat.tools import ChatScope
    from log_whisperer.llm import LLMError

    settings = _settings()
    llm = _provider(settings, provider, model)
    with Store(_db_path(db)) as store:
        incident = None
        if not global_:
            incident = store.get_incident(incident_id or "")
            if incident is None:
                typer.echo("error: give an existing incident id or use --global", err=True)
                raise typer.Exit(1)
        svc = ChatService(store, llm, settings)
        session = svc.new_session(ChatScope("incident" if incident else "global", incident))
        typer.echo("Ask a question (empty line to quit).")
        while question := typer.prompt(">", default="", show_default=False).strip():
            try:
                ans = svc.ask(session, question)
            except LLMError as exc:
                typer.echo(f"error: {exc}", err=True)
                continue
            for s in ans.sentences:
                typer.echo(f"  {s.text}  [{len(s.event_ids)} cited: {', '.join(s.event_ids[:3])}]")
            for t in ans.no_data:
                typer.echo(f"  {t}  [no matching data]")
            for r in ans.rejected:
                typer.echo(f"  (dropped: {r.reason}) {r.text[:80]}")


@app.command("eval")
def eval_(
    provider: ProviderOpt = None,
    model: ModelOpt = None,
    cases: Annotated[Path, typer.Option(help="Directory of case YAML files.")] = Path("../eval/cases"),
    root: Annotated[Path, typer.Option(help="Base directory for case file paths.")] = Path(".."),
    out: Annotated[Path, typer.Option(help="Results directory.")] = Path("../eval/results"),
    only: Annotated[list[str] | None, typer.Option(help="Run only these case names.")] = None,
) -> None:
    """Measure narrative accuracy for one provider/model."""
    from log_whisperer.evaluation.cases import load_cases
    from log_whisperer.evaluation.runner import run_eval, write_report

    settings = _settings()
    llm = _provider(settings, provider, model)
    selected = [c for c in load_cases(cases) if not only or c.name in only]
    report = run_eval(selected, llm, settings, root)
    for c in report.cases:
        status = c.skipped and f"skipped ({c.skipped})" or c.error and f"error ({c.error})" or \
            " ".join(f"{k}={v:.2f}" for k, v in c.metrics.items())
        typer.echo(f"{c.name:<32} {status}")
    js, md = write_report(report, out)
    typer.echo(f"\naggregate: {report.aggregate}\nresults: {js}\nsummary: {md}")


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address (default from config).")] = None,
    port: Annotated[int | None, typer.Option(help="Port (default from config).")] = None,
    live: Annotated[bool, typer.Option(help="Also start live ingestion.")] = False,
) -> None:
    """Run the REST API (docs at /api/docs)."""
    import uvicorn

    from log_whisperer.api.app import create_app

    settings = _settings()
    settings.live.autostart = live or settings.live.autostart
    uvicorn.run(create_app(settings), host=host or settings.api.host, port=port or settings.api.port)


@app.command()
def live(
    db: DbOpt = None,
    port: Annotated[int | None, typer.Option(help="Syslog UDP/TCP port (default from config).")] = None,
    tail: Annotated[list[Path] | None, typer.Option(help="Files to follow (repeatable).")] = None,
) -> None:
    """Receive syslog and tail files in the foreground (Ctrl+C to stop)."""
    import asyncio

    from log_whisperer.live.pipeline import LivePipeline

    settings = _settings()
    if port is not None:
        settings.live.syslog_port = port
    if tail:
        settings.live.tail_paths = tail

    async def run() -> None:
        with Store(_db_path(db)) as store:
            p = LivePipeline(store, settings)
            await p.start()
            typer.echo(f"listening: {', '.join(p.status.sources)}")
            try:
                while True:
                    await asyncio.sleep(5)
                    s = p.status
                    typer.echo(f"events={s.events_total} unparsed={s.unparsed_total} "
                               f"detections={s.detections_total} flushes={s.flushes}")
            finally:
                await p.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        typer.echo("stopped")


@app.command()
def actions(incident_id: str, db: DbOpt = None, provider: ProviderOpt = None, model: ModelOpt = None) -> None:
    """Suggest cited response actions (advisory only, nothing is executed)."""
    from log_whisperer.response.actions import ADVISORY, suggest_actions

    settings = _settings()
    llm = _provider(settings, provider, model)
    with Store(_db_path(db)) as store:
        acts, rejected = suggest_actions(store, incident_id, llm, settings)
    typer.echo(f"({ADVISORY})")
    for a in acts:
        typer.echo(f"[{a.priority}] {a.action}\n    why: {a.rationale}  ({len(a.event_ids)} cited events)")
    for r in rejected:
        typer.echo(f"  (dropped: {r.reason}) {r.text[:80]}")


@app.command()
def report(
    incident_id: str,
    db: DbOpt = None,
    format: Annotated[str, typer.Option("--format", help="md | pdf")] = "md",
    out: Annotated[Path | None, typer.Option(help="Output file (default: incident-<id>.<format>).")] = None,
) -> None:
    """Export an incident report as Markdown or PDF."""
    from log_whisperer.report.pdf import PdfUnavailable, render_pdf
    from log_whisperer.report.service import build_report

    with Store(_db_path(db)) as store:
        try:
            markdown = build_report(store, incident_id)
        except KeyError as exc:
            typer.echo(f"error: {exc.args[0]}", err=True)
            raise typer.Exit(1) from exc
    target = out or Path(f"incident-{incident_id}.{format}")
    if format == "pdf":
        try:
            target.write_bytes(render_pdf(markdown, f"Incident {incident_id}"))
        except PdfUnavailable as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from exc
    else:
        target.write_text(markdown, encoding="utf-8")
    typer.echo(f"wrote {target}")


@rules_app.command("draft")
def rules_draft(incident_id: str, db: DbOpt = None, provider: ProviderOpt = None, model: ModelOpt = None) -> None:
    """Draft a Sigma rule from an incident and validate it against the incident's events."""
    from log_whisperer.rulegen.draft import draft_rule

    settings = _settings()
    llm = _provider(settings, provider, model)
    with Store(_db_path(db)) as store:
        r = draft_rule(store, incident_id, llm, settings, settings.detection.drafts_dir)
    typer.echo(f"status: {r.status}" + (f" ({r.reason})" if r.reason else ""))
    typer.echo(f"matched incident events: {len(r.matched_event_ids)}")
    if r.path:
        typer.echo(f"saved: {r.path} (review, then move to rules/custom/ to activate)")
    typer.echo("\n" + r.yaml)


@app.command()
def openapi(out: Annotated[Path, typer.Option(help="Output JSON file.")] = Path("openapi.json")) -> None:
    """Write the API's OpenAPI schema (used to generate frontend types)."""
    import json

    from log_whisperer.api.app import create_app

    out.write_text(json.dumps(create_app(_settings()).openapi(), indent=1), encoding="utf-8")
    typer.echo(f"wrote {out}")


@rules_app.command("check")
def rules_check(
    rules: Annotated[list[Path] | None, typer.Option(help="Rule directories.")] = None,
    show: Annotated[bool, typer.Option(help="List every unsupported rule.")] = False,
) -> None:
    """Load and compile rules; report what is unsupported."""
    from collections import Counter

    from log_whisperer.detection.sigma_rules import load_rules

    _, report = load_rules(rules or _settings().detection.sigma_dirs)
    typer.echo(f"loaded={report.loaded} unsupported={len(report.unsupported)}")
    reasons = Counter(reason.split(":")[0] for _, reason in report.unsupported)
    for reason, n in reasons.most_common():
        typer.echo(f"{n:6d}  {reason}")
    if show:
        for name, reason in report.unsupported:
            typer.echo(f"  {name}: {reason}")


@rules_app.command("sync")
def rules_sync(
    tag: Annotated[str | None, typer.Option(help="SigmaHQ release tag (default: latest).")] = None,
    dest: Annotated[Path, typer.Option(help="Target directory.")] = Path("../rules/sigma"),
) -> None:
    """Download a pinned SigmaHQ snapshot filtered to supported logsources."""
    from log_whisperer.rules_sync import sync

    tag, count = sync(dest, tag)
    typer.echo(f"SigmaHQ {tag}: {count} rule files -> {dest}")

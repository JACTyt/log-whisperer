"""Derive normalized columns from native Windows event field names.

Shared by the EVTX parser and the Windows JSON (Security-Datasets) parser so both
produce identical events for identical records.
"""

import re
from typing import Any

from log_whisperer.ids import normalize_user

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

_CN = re.compile(r"^CN=([^,]+)", re.IGNORECASE)

# Security channel: EventID -> action
_SECURITY_ACTIONS = {
    "4624": "logon",
    "4625": "logon",
    "4634": "logoff",
    "4648": "explicit_logon",
    "4672": "special_privileges",
    "4688": "process_start",
    "4697": "service_installed",
    "4720": "user_created",
    "4726": "user_deleted",
    "4728": "group_member_added",
    "4732": "group_member_added",
    "4756": "group_member_added",
    "4768": "kerberos_tgt",
    "4769": "kerberos_service_ticket",
    "4771": "kerberos_preauth",
    "4776": "credential_validation",
    "5140": "share_access",
    "5145": "share_access",
    "1102": "log_cleared",
}

_SYSMON_ACTIONS = {
    "1": "process_start",
    "3": "network_connection",
    "7": "image_loaded",
    "8": "create_remote_thread",
    "10": "process_access",
    "11": "file_created",
    "12": "registry_event",
    "13": "registry_set",
    "22": "dns_query",
}


def clean_ip(value: Any) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    if v in ("", "-"):
        return None
    return v.removeprefix("::ffff:")


def _str(value: Any) -> str | None:
    if value is None:
        return None
    v = str(value)
    return v or None


def _status_outcome(status: str | None) -> str | None:
    if status is None:
        return "success"
    try:
        return "success" if int(status, 16) == 0 else "failure"
    except ValueError:
        return None


def _member_user(fields: dict[str, Any]) -> str | None:
    member = _str(fields.get("MemberName"))
    if member and (m := _CN.match(member)):
        return normalize_user(m.group(1))
    return normalize_user(member)


def add_sigma_aliases(fields: dict[str, Any]) -> dict[str, Any]:
    """Security 4688 uses different names than Sysmon 1; Sigma process_creation rules use Sysmon's."""
    if str(fields.get("EventID")) == "4688" and fields.get("Channel") == SECURITY:
        fields.setdefault("Image", fields.get("NewProcessName"))
        fields.setdefault("ParentImage", fields.get("ParentProcessName"))
        if fields.get("SubjectUserName"):
            domain = fields.get("SubjectDomainName")
            fields.setdefault("User", f"{domain}\\{fields['SubjectUserName']}" if domain else fields["SubjectUserName"])
    return fields


def derive(fields: dict[str, Any]) -> dict[str, Any]:
    """Return normalized column values for a flat dict of native Windows fields."""
    eid = _str(fields.get("EventID"))
    channel = _str(fields.get("Channel"))
    out: dict[str, Any] = {
        "event_code": eid,
        "channel": channel,
        "host": _str(fields.get("Computer")),
        "user": normalize_user(_str(fields.get("SubjectUserName") or fields.get("User"))),
        "src_ip": None,
        "dst_ip": None,
        "process": None,
        "command_line": None,
        "action": None,
        "outcome": None,
    }

    if channel == SECURITY:
        out["action"] = _SECURITY_ACTIONS.get(eid)
        if eid in ("4624", "4625", "4648", "4768", "4769", "4771", "4776"):
            out["user"] = normalize_user(_str(fields.get("TargetUserName")))
            out["src_ip"] = clean_ip(fields.get("IpAddress"))
            out["process"] = _str(fields.get("ProcessName"))
        if eid == "4624":
            out["outcome"] = "success"
        elif eid == "4625":
            out["outcome"] = "failure"
        elif eid in ("4768", "4769", "4771", "4776"):
            out["outcome"] = _status_outcome(_str(fields.get("Status")))
        elif eid == "4688":
            out["process"] = _str(fields.get("NewProcessName"))
            out["command_line"] = _str(fields.get("CommandLine"))
        elif eid in ("4720", "4726"):
            out["user"] = normalize_user(_str(fields.get("TargetUserName")))
        elif eid in ("4728", "4732", "4756"):
            out["user"] = _member_user(fields)
        elif eid == "4697":
            out["process"] = _str(fields.get("ServiceFileName"))
        elif eid in ("5140", "5145"):
            out["src_ip"] = clean_ip(fields.get("IpAddress"))
    elif channel == SYSMON:
        out["action"] = _SYSMON_ACTIONS.get(eid)
        out["process"] = _str(fields.get("Image") or fields.get("SourceImage"))
        out["command_line"] = _str(fields.get("CommandLine"))
        if eid == "3":
            out["src_ip"] = clean_ip(fields.get("SourceIp"))
            out["dst_ip"] = clean_ip(fields.get("DestinationIp"))
    elif channel == POWERSHELL and eid == "4104":
        out["action"] = "script_block"
        out["command_line"] = _str(fields.get("ScriptBlockText"))
    elif channel == "System" and eid == "7045":
        out["action"] = "service_installed"
        out["process"] = _str(fields.get("ImagePath"))

    return out

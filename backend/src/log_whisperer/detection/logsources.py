"""Map Sigma logsources to SQL filters over the normalized `events` columns (DESIGN §7.1)."""

from sigma.rule import SigmaLogSource

SYSMON = "Microsoft-Windows-Sysmon/Operational"
WIN = "source_type IN ('evtx', 'winjson')"

_WINDOWS_SERVICES = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "sysmon": SYSMON,
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "DNS Server",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
}

# category -> list of (channel, [event codes])
_WINDOWS_CATEGORIES: dict[str, list[tuple[str, list[str]]]] = {
    "process_creation": [(SYSMON, ["1"]), ("Security", ["4688"])],
    "network_connection": [(SYSMON, ["3"])],
    "process_termination": [(SYSMON, ["5"])],
    "driver_load": [(SYSMON, ["6"])],
    "image_load": [(SYSMON, ["7"])],
    "create_remote_thread": [(SYSMON, ["8"])],
    "raw_access_thread": [(SYSMON, ["9"])],
    "process_access": [(SYSMON, ["10"])],
    "file_event": [(SYSMON, ["11"])],
    "registry_add": [(SYSMON, ["12"])],
    "registry_delete": [(SYSMON, ["12"])],
    "registry_set": [(SYSMON, ["13"])],
    "registry_rename": [(SYSMON, ["14"])],
    "registry_event": [(SYSMON, ["12", "13", "14"])],
    "create_stream_hash": [(SYSMON, ["15"])],
    "pipe_created": [(SYSMON, ["17", "18"])],
    "wmi_event": [(SYSMON, ["19", "20", "21"])],
    "dns_query": [(SYSMON, ["22"])],
    "file_delete": [(SYSMON, ["23", "26"])],
    "file_change": [(SYSMON, ["2"])],
    "process_tampering": [(SYSMON, ["25"])],
    "file_executable_detected": [(SYSMON, ["29"])],
    "ps_script": [("Microsoft-Windows-PowerShell/Operational", ["4104"])],
    "ps_module": [("Microsoft-Windows-PowerShell/Operational", ["4103"])],
    "ps_classic_start": [("Windows PowerShell", ["400"])],
}

_WEB_PRODUCTS = {None, "apache", "nginx", "iis", "web"}


def _q(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def logsource_sql(ls: SigmaLogSource) -> str | None:
    """SQL filter selecting the events a rule applies to, or None if unsupported."""
    product, category, service = ls.product, ls.category, ls.service
    if category == "webserver" and product in _WEB_PRODUCTS and service is None:
        return "source_type = 'web'"
    if product == "windows":
        if category is None and service in _WINDOWS_SERVICES:
            return f"{WIN} AND channel = {_q(_WINDOWS_SERVICES[service])}"
        if category in _WINDOWS_CATEGORIES and service is None:
            parts = [
                f"(channel = {_q(ch)} AND event_code IN ({', '.join(_q(c) for c in codes)}))"
                for ch, codes in _WINDOWS_CATEGORIES[category]
            ]
            return f"{WIN} AND ({' OR '.join(parts)})"
        return None
    if product == "linux" and category is None:
        # auth.log and live syslog carry the same text; service-specific rules simply won't match others.
        return "source_type IN ('authlog', 'syslog')"
    return None

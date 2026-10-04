"""Map Sigma `logsource` blocks to Windows channels and EventIDs.

A rule is routed to one or more ``(channel, event_ids)`` targets. ``event_ids``
is ``None`` when every event of the channel must be evaluated (service-only
rules, whose detection usually filters on EventID itself).
"""

from __future__ import annotations

from typing import Any

from tinybrother.engine.errors import UnsupportedRule

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS_OP = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC = "Windows PowerShell"
SECURITY = "Security"

Target = tuple[str, frozenset[int] | None]

# category -> list of (channel, event ids)
CATEGORIES: dict[str, list[tuple[str, tuple[int, ...]]]] = {
    "process_creation": [(SYSMON, (1,)), (SECURITY, (4688,))],
    "network_connection": [(SYSMON, (3,))],
    "sysmon_status": [(SYSMON, (4, 16))],
    "process_termination": [(SYSMON, (5,))],
    "driver_load": [(SYSMON, (6,))],
    "image_load": [(SYSMON, (7,))],
    "create_remote_thread": [(SYSMON, (8,))],
    "raw_access_thread": [(SYSMON, (9,))],
    "process_access": [(SYSMON, (10,))],
    "file_event": [(SYSMON, (11,))],
    "file_change": [(SYSMON, (2,))],
    "registry_add": [(SYSMON, (12,))],
    "registry_delete": [(SYSMON, (12,))],
    "registry_set": [(SYSMON, (13,))],
    "registry_rename": [(SYSMON, (14,))],
    "registry_event": [(SYSMON, (12, 13, 14))],
    "create_stream_hash": [(SYSMON, (15,))],
    "pipe_created": [(SYSMON, (17, 18))],
    "wmi_event": [(SYSMON, (19, 20, 21))],
    "dns_query": [(SYSMON, (22,))],
    "file_delete": [(SYSMON, (23, 26))],
    "clipboard_capture": [(SYSMON, (24,))],
    "process_tampering": [(SYSMON, (25,))],
    "file_delete_detected": [(SYSMON, (26,))],
    "file_block_executable": [(SYSMON, (27,))],
    "file_block_shredding": [(SYSMON, (28,))],
    "file_executable_detected": [(SYSMON, (29,))],
    "sysmon_error": [(SYSMON, (255,))],
    "ps_module": [(PS_OP, (4103,))],
    "ps_script": [(PS_OP, (4104,))],
    "ps_classic_start": [(PS_CLASSIC, (400,))],
    "ps_classic_provider_start": [(PS_CLASSIC, (600,))],
    "ps_classic_script": [(PS_CLASSIC, (800,))],
}

# service -> channel(s)
SERVICES: dict[str, tuple[str, ...]] = {
    "security": (SECURITY,),
    "system": ("System",),
    "application": ("Application",),
    "sysmon": (SYSMON,),
    "powershell": (PS_OP,),
    "powershell-classic": (PS_CLASSIC,),
    "windefend": ("Microsoft-Windows-Windows Defender/Operational",),
    "taskscheduler": ("Microsoft-Windows-TaskScheduler/Operational",),
    "wmi": ("Microsoft-Windows-WMI-Activity/Operational",),
    "bits-client": ("Microsoft-Windows-Bits-Client/Operational",),
    "codeintegrity-operational": ("Microsoft-Windows-CodeIntegrity/Operational",),
    "firewall-as": ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",),
    "dns-client": ("Microsoft-Windows-DNS Client Events/Operational",),
    "ntlm": ("Microsoft-Windows-NTLM/Operational",),
    "driver-framework": ("Microsoft-Windows-DriverFrameworks-UserMode/Operational",),
    "terminalservices-localsessionmanager": (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ),
    "smbclient-security": ("Microsoft-Windows-SmbClient/Security",),
    "openssh": ("OpenSSH/Operational",),
    "shell-core": ("Microsoft-Windows-Shell-Core/Operational",),
    "ldap": ("Microsoft-Windows-LDAP-Client/Debug",),
    "appxdeployment-server": ("Microsoft-Windows-AppXDeploymentServer/Operational",),
    "appxpackaging-om": ("Microsoft-Windows-AppxPackaging/Operational",),
    "appmodel-runtime": ("Microsoft-Windows-AppModel-Runtime/Admin",),
    "security-mitigations": (
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ),
    "diagnosis-scripted": ("Microsoft-Windows-Diagnosis-Scripted/Operational",),
    "capi2": ("Microsoft-Windows-CAPI2/Operational",),
    "lsa-server": ("Microsoft-Windows-LSA/Operational",),
    "smbserver-connectivity": ("Microsoft-Windows-SMBServer/Connectivity",),
    "certificateservicesclient-lifecycle-system": (
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    ),
    "applocker": (
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ),
}


def targets_for(logsource: dict[str, Any]) -> list[Target]:
    product = str(logsource.get("product", "windows")).lower()
    if product != "windows":
        raise UnsupportedRule(f"product {product!r} is not collected")
    category = logsource.get("category")
    service = logsource.get("service")

    if category:
        category = str(category).lower()
        if category not in CATEGORIES:
            raise UnsupportedRule(f"unknown category {category!r}")
        targets = [(ch, frozenset(ids)) for ch, ids in CATEGORIES[category]]
        if service:  # e.g. category: process_creation + service: sysmon
            allowed = set(SERVICES.get(str(service).lower(), ()))
            targets = [t for t in targets if t[0] in allowed] or targets
        return targets
    if service:
        service = str(service).lower()
        if service not in SERVICES:
            raise UnsupportedRule(f"unknown service {service!r}")
        return [(ch, None) for ch in SERVICES[service]]
    raise UnsupportedRule("logsource has neither category nor service")


# Security 4688 uses different names than Sysmon 1 for the same data
_ALIASES: dict[tuple[str, int], dict[str, str]] = {
    (SECURITY, 4688): {
        "Image": "NewProcessName",
        "ParentImage": "ParentProcessName",
        "ProcessId": "NewProcessId",
        "User": "SubjectUserName",
    },
}


class _Lowered(str):
    pass


def lowered(value: str) -> str:
    """Wrap `value` so predicates can reuse `value.low` instead of lowering again."""
    w = _Lowered(value)
    w.low = value.lower()  # type: ignore[attr-defined]
    return w


def prepare_fields(channel: str, event_id: int, fields: dict[str, Any]) -> dict[str, Any]:
    """Return the field view rules should see (aliases + joined classic Data).

    String values are wrapped so their lower-case form is computed only once.
    """
    view = dict(fields)
    for target, source in _ALIASES.get((channel, event_id), {}).items():
        if target not in view and source in view:
            view[target] = view[source]
    if "Data" not in view and "Data_0" in view:
        parts = [str(view[k]) for k in sorted(
            (k for k in view if k.startswith("Data_")), key=lambda k: int(k[5:])
        ) if view[k] is not None]
        view["Data"] = "\n".join(parts)
    view.setdefault("Channel", channel)
    for k, v in view.items():
        if isinstance(v, str):
            view[k] = lowered(v)
    return view

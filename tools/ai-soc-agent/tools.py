"""Read-only investigation tools.

These are the ONLY way the agent can touch Azure data. The model never receives
credentials, never sees a connection string, and never supplies KQL. It picks a
tool by name and supplies typed arguments; this module owns the query text.

The security model, in order of importance:

1. **No caller-supplied KQL.** Every query is a fixed template in this file.
2. **Arguments are validated against strict allowlists** before they are
   interpolated, so a value can never terminate a string literal or append a
   clause. Anything that fails validation is rejected, not escaped-and-hoped.
3. **Read-only credentials.** The Managed Identity behind these queries holds a
   reader role on one workspace and nothing else.
4. **Bounded cost.** Every query has a time ceiling, a row cap, and a projection
   to the columns that matter.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Bounds. `hours` is clamped rather than rejected: an over-eager model asking for
# a year of data should get a week, not an error.
DEFAULT_HOURS = 24
# How far past the anchor to look when a window is anchored to an incident.
DEFAULT_HOURS_AFTER = 6
MAX_HOURS = 168  # 7 days
MAX_ROWS = 50
# Sentinel rows carry whole entity and custom-detail blobs, so they are far
# larger than an application event row. Fewer of them.
ALERT_MAX_ROWS = 15
# Hard ceiling on the JSON handed back to the model. Tool output feeds straight
# into the next prompt, so an unbounded result is an unbounded bill - and a 429.
MAX_RESULT_CHARS = 12000
QUERY_TIMEOUT_SECONDS = 60

# Allowlists. Deliberately narrow; widen only with a reason.
USER_PATTERN = re.compile(r"^[A-Za-z0-9._@+\-]{3,128}$")
PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._/~\-]{0,255}$")
EVENT_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


# Records the KQL actually executed during one analysis, so the answer can carry
# its own working. Context-local, so concurrent requests never mix.
_QUERY_LOG: ContextVar[list | None] = ContextVar("query_log", default=None)
_CURRENT_TOOL: ContextVar[str] = ContextVar("current_tool", default="")

# Incident status as Sentinel reported it. Recorded from the tool result rather
# than taken from the model's prose, so the status shown to an analyst is the
# real one and cannot be invented or go stale in a paraphrase.
_INCIDENT: ContextVar[dict | None] = ContextVar("incident_facts", default=None)


def start_query_log() -> list[dict[str, Any]]:
    """Begin recording queries and incident facts for this analysis."""
    log: list[dict[str, Any]] = []
    _QUERY_LOG.set(log)
    _INCIDENT.set(None)
    return log


def get_incident_facts() -> dict[str, Any] | None:
    """The incident this analysis looked up, if any."""
    return _INCIDENT.get()


def _record(query: str, row_count: int) -> None:
    log = _QUERY_LOG.get()
    if log is None:
        return
    log.append(
        {
            "tool": _CURRENT_TOOL.get() or "unknown",
            "kql": query.strip(),
            "row_count": row_count,
        }
    )


class ToolError(RuntimeError):
    """A tool could not run. The message is safe to show the model."""


class ToolConfigurationError(ToolError):
    """Log Analytics access is not configured."""


def is_configured() -> bool:
    """True when a workspace is configured, without raising."""
    return bool(os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "").strip())


def _workspace_id() -> str:
    workspace = os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "").strip()
    if not workspace:
        raise ToolConfigurationError(
            "missing environment variable: AZURE_LOG_ANALYTICS_WORKSPACE_ID"
        )
    return workspace


@lru_cache(maxsize=1)
def _client():
    """Log Analytics client authenticated by Managed Identity.

    `DefaultAzureCredential` uses the container's Managed Identity in Azure and
    the developer's `az login` locally, so no secret exists in either case.
    Imported lazily so the app still starts if the SDK or identity is absent.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise ToolConfigurationError("azure query SDK is not installed") from exc

    return LogsQueryClient(DefaultAzureCredential())


# --- argument validation ----------------------------------------------------

def _clean_hours(hours: Any, default: int = DEFAULT_HOURS) -> int:
    try:
        value = int(hours)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, MAX_HOURS))


def _clean_anchor(around: Any) -> datetime | None:
    """Parse an anchor timestamp, or None to mean 'now'.

    The value is parsed into a real datetime and later re-serialised by us, so
    whatever the model sends can never reach the query as text.
    """
    if around in (None, "", "now"):
        return None
    text = str(around).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ToolError(
            f"invalid timestamp: {str(around)[:40]!r}. Expected ISO-8601, "
            "for example 2026-08-18T03:09:07Z"
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _time_filter(anchor: datetime | None, hours_before: int, hours_after: int) -> str:
    """Build the time predicate.

    Without an anchor this is a lookback from now. With one — the incident's own
    timestamp — it becomes a window bracketing the event, which is what actually
    matters: an incident from last week has no activity in the last 24 hours, and
    what happened *after* it is often the point.
    """
    if anchor is None:
        return f"| where TimeGenerated > ago({hours_before}h)"
    start = anchor - timedelta(hours=hours_before)
    end = anchor + timedelta(hours=hours_after)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (
        f"| where TimeGenerated between "
        f"(datetime({start.strftime(fmt)}) .. datetime({end.strftime(fmt)}))"
    )


def _clean_user(user: Any) -> str:
    value = str(user or "").strip()
    if not USER_PATTERN.match(value):
        raise ToolError(
            "invalid user identifier: expected a user id or email address "
            "containing only letters, digits, and . _ @ + -"
        )
    return value


def _clean_ip(ip: Any) -> str:
    value = str(ip or "").strip()
    try:
        # Rejects anything that is not a literal address, which also guarantees
        # the value is safe to interpolate.
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ToolError(f"invalid IP address: {value[:60]!r}")


RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9._/\-]{3,200}$")


def _clean_resource(resource: Any) -> str:
    """A resource name or a fragment of a resource id."""
    value = str(resource or "").strip()
    if not RESOURCE_PATTERN.match(value):
        raise ToolError(
            "invalid resource: expected a resource name or resource-id fragment, "
            "for example 'example-api'"
        )
    return value


def _clean_path(path: Any) -> str:
    value = str(path or "").strip()
    if not PATH_PATTERN.match(value):
        raise ToolError(
            "invalid request path: expected something like /api/auth/refresh"
        )
    return value


# --- query execution --------------------------------------------------------

# --- telemetry schema (configurable) ----------------------------------------
#
# Every tool reads the same shape out of one table. Applications instrument
# themselves differently, so the table and the field names are configuration
# rather than assumptions: set them for your environment and the tools follow.
#
# The defaults below describe an application that writes security events to the
# Application Insights `AppEvents` table with its detail in the `Properties`
# JSON column. Override via environment variables to match your own schema.
#
#   TELEMETRY_TABLE       table holding application security events
#   TELEMETRY_PROPERTIES  column holding the event detail as JSON
#   TELEMETRY_FIELD_*     property name for each field the tools read
#   PLATFORM_USER_AGENTS  comma-separated agents that indicate server-side
#                         (edge/serverless) callers rather than end users

TABLE = os.environ.get("TELEMETRY_TABLE", "AppEvents").strip() or "AppEvents"
PROPS = os.environ.get("TELEMETRY_PROPERTIES", "Properties").strip() or "Properties"

FIELDS = {
    "user":       os.environ.get("TELEMETRY_FIELD_USER", "userId"),
    "email":      os.environ.get("TELEMETRY_FIELD_EMAIL", "email"),
    "ip":         os.environ.get("TELEMETRY_FIELD_IP", "ipAddress"),
    "path":       os.environ.get("TELEMETRY_FIELD_PATH", "path"),
    "method":     os.environ.get("TELEMETRY_FIELD_METHOD", "method"),
    "severity":   os.environ.get("TELEMETRY_FIELD_SEVERITY", "severity"),
    "user_agent": os.environ.get("TELEMETRY_FIELD_USER_AGENT", "userAgent"),
}

# Identifiers are interpolated into KQL, so constrain them the same way user
# input is constrained. A bad config value should fail loudly, not build a query.
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
for _name, _value in [("TELEMETRY_TABLE", TABLE), ("TELEMETRY_PROPERTIES", PROPS)] + \
                     [("TELEMETRY_FIELD_" + k.upper(), v) for k, v in FIELDS.items()]:
    if not _IDENT.match(_value):
        raise ToolConfigurationError(f"invalid identifier for {_name}: {_value!r}")

# Server-side handlers (edge functions, serverless) record the platform's egress
# address rather than the caller's. Naming that distinction matters: otherwise a
# handful of rotating cloud IPs reads as a handful of distinct clients.
_PLATFORM_AGENTS = [
    a.strip() for a in os.environ.get(
        "PLATFORM_USER_AGENTS", "Edge Functions,Lambda,node-fetch,axios,undici"
    ).split(",") if a.strip() and "'" not in a
]
_AGENT_LIST = ", ".join("'%s'" % a for a in _PLATFORM_AGENTS) or "''"

_BASE = """
{table}
{{time_filter}}
| extend P = parse_json({props})
| extend EventUserId = tostring(P.{f_user}),
         EventEmail = tostring(P.{f_email}),
         RawIp = tostring(P.{f_ip}),
         Path = tostring(P.{f_path}),
         Method = tostring(P.{f_method}),
         Severity = tostring(P.{f_severity}),
         UserAgent = tostring(P.{f_user_agent})
| extend SourceIp = trim(@'[\\s]+', tostring(split(RawIp, ',')[0]))
| extend IpProvenance = case(
      UserAgent has_any ({agents}),
          'platform-egress - NOT the end user, do not treat as a client IP',
      RawIp contains ',', 'client (first hop of forwarded chain)',
      'unverified - single address, no forwarded chain')
""".format(
    table=TABLE, props=PROPS, agents=_AGENT_LIST,
    f_user=FIELDS["user"], f_email=FIELDS["email"], f_ip=FIELDS["ip"],
    f_path=FIELDS["path"], f_method=FIELDS["method"],
    f_severity=FIELDS["severity"], f_user_agent=FIELDS["user_agent"],
)

_PROJECT = """
| project TimeGenerated, Event = Name, EventUserId, EventEmail, SourceIp,
          IpProvenance, Path, Method, Severity, UserAgent
| order by TimeGenerated desc
| take {rows}
"""


def _run(query: str) -> list[dict[str, Any]]:
    """Execute a read-only KQL query and return rows as dictionaries."""
    from azure.core.exceptions import AzureError
    from azure.monitor.query import LogsQueryStatus

    client = _client()
    try:
        response = client.query_workspace(
            workspace_id=_workspace_id(),
            query=query,
            timespan=None,  # the query carries its own time filter
            server_timeout=QUERY_TIMEOUT_SECONDS,
        )
    except AzureError as exc:
        logger.exception("Log Analytics query failed")
        raise ToolError(f"log query failed: {type(exc).__name__}") from exc

    if response.status == LogsQueryStatus.FAILURE:
        logger.error("Log Analytics returned failure: %s", getattr(response, "partial_error", ""))
        raise ToolError("log query failed")

    tables = getattr(response, "tables", None) or getattr(response, "partial_data", [])
    rows: list[dict[str, Any]] = []
    for table in tables:
        columns = list(table.columns)
        for row in table.rows:
            record = {}
            for name, value in zip(columns, row):
                record[name] = value.isoformat() if hasattr(value, "isoformat") else value
            rows.append(record)

    _record(query, len(rows))
    return rows


# --- the tools --------------------------------------------------------------

def get_user_activity(user: str, hours: int = DEFAULT_HOURS, around: str | None = None,
                      hours_after: int = DEFAULT_HOURS_AFTER) -> list[dict[str, Any]]:
    """Everything a given user id or email did in the window."""
    user_value = _clean_user(user)
    time_filter = _time_filter(_clean_anchor(around), _clean_hours(hours),
                               _clean_hours(hours_after, DEFAULT_HOURS_AFTER))
    query = (
        _BASE.format(time_filter=time_filter)
        + f"| where EventUserId =~ '{user_value}' or EventEmail =~ '{user_value}'"
        + _PROJECT.format(rows=MAX_ROWS)
    )
    return _run(query)


def get_ip_activity(ip: str, hours: int = DEFAULT_HOURS, around: str | None = None,
                    hours_after: int = DEFAULT_HOURS_AFTER) -> list[dict[str, Any]]:
    """Everything seen from a given source IP in the window."""
    ip_value = _clean_ip(ip)
    time_filter = _time_filter(_clean_anchor(around), _clean_hours(hours),
                               _clean_hours(hours_after, DEFAULT_HOURS_AFTER))
    query = (
        _BASE.format(time_filter=time_filter)
        + f"| where RawIp contains '{ip_value}'"
        + _PROJECT.format(rows=MAX_ROWS)
    )
    return _run(query)


def get_auth_events(user: str | None = None, hours: int = DEFAULT_HOURS,
                    around: str | None = None,
                    hours_after: int = DEFAULT_HOURS_AFTER) -> list[dict[str, Any]]:
    """Authentication events (login, password reset), optionally for one user."""
    time_filter = _time_filter(_clean_anchor(around), _clean_hours(hours),
                               _clean_hours(hours_after, DEFAULT_HOURS_AFTER))
    query = _BASE.format(time_filter=time_filter) + (
        "| where Name in ('login_success', 'login_failed', "
        "'password_reset_requested', 'password_reset_success')"
    )
    if user:
        user_value = _clean_user(user)
        query += f"\n| where EventUserId =~ '{user_value}' or EventEmail =~ '{user_value}'"
    return _run(query + _PROJECT.format(rows=MAX_ROWS))


def get_related_requests(path: str, hours: int = DEFAULT_HOURS, around: str | None = None,
                         hours_after: int = DEFAULT_HOURS_AFTER) -> list[dict[str, Any]]:
    """Events recorded against a given request path."""
    path_value = _clean_path(path)
    time_filter = _time_filter(_clean_anchor(around), _clean_hours(hours),
                               _clean_hours(hours_after, DEFAULT_HOURS_AFTER))
    query = (
        _BASE.format(time_filter=time_filter)
        + f"| where Path =~ '{path_value}'"
        + _PROJECT.format(rows=MAX_ROWS)
    )
    return _run(query)


# --- Sentinel ---------------------------------------------------------------

def _is_usable_account(value: str) -> bool:
    """Whether an account entity is actually an identifier.

    Some analytic rules map the wrong column into the Account entity and Sentinel
    faithfully records things like AccountName "3". Passing that on invites the
    model to look up a user called "3"; better to drop it and say why.
    """
    return len(value) >= 6 and not value.isdigit()


def _parse_entities(raw: Any) -> dict[str, list[str]]:
    """Pull the useful entities out of a SecurityAlert `Entities` blob.

    Sentinel stores them as a JSON array of typed objects. This is where the
    source IP lives for app alerts, which the Slack message often omits.
    Degenerate account entities are separated out rather than silently dropped,
    so the analysis can report a broken detection rule instead of guessing.
    """
    found: dict[str, list[str]] = {
        "ips": [], "accounts": [], "urls": [], "hosts": [], "unusable_accounts": []
    }
    try:
        entities = json.loads(raw) if isinstance(raw, str) and raw.strip() else []
    except ValueError:
        return found
    if not isinstance(entities, list):
        return found

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        kind = str(entity.get("Type", "")).lower()
        if kind == "ip" and entity.get("Address"):
            found["ips"].append(str(entity["Address"]))
        elif kind == "account":
            name = (
                entity.get("UserPrincipalName")
                or entity.get("DisplayName")
                or entity.get("AccountName")
            )
            if name:
                bucket = "accounts" if _is_usable_account(str(name)) else "unusable_accounts"
                found[bucket].append(str(name))
        elif kind == "url" and entity.get("Url"):
            found["urls"].append(str(entity["Url"]))
        elif kind == "host" and entity.get("HostName"):
            found["hosts"].append(str(entity["HostName"]))

    return {k: sorted(set(v)) for k, v in found.items() if v}


def _parse_custom_details(raw: Any) -> dict[str, Any]:
    """Extract the analytic rule's Custom Details from ExtendedProperties.

    Sentinel nests this as a JSON string inside a JSON string. The rule author
    put the interesting fields here (UserId, Path, Method, UserAgent, Email),
    so it is worth unwrapping rather than handing the model the raw blob.
    """
    try:
        props = json.loads(raw) if isinstance(raw, str) and raw.strip() else {}
        details = props.get("Custom Details")
        parsed = json.loads(details) if isinstance(details, str) else (details or {})
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    # Custom Details wraps every value in a list; unwrap single-item ones.
    return {
        key: (value[0] if isinstance(value, list) and len(value) == 1 else value)
        for key, value in parsed.items()
    }


def get_incident(incident_number: int) -> list[dict[str, Any]]:
    """Full Sentinel incident detail, including the entities its alerts named."""
    try:
        number = int(incident_number)
    except (TypeError, ValueError):
        raise ToolError(f"invalid incident number: {incident_number!r}")
    if not 0 < number < 1_000_000:
        raise ToolError(f"invalid incident number: {number}")

    query = f"""
SecurityIncident
| where IncidentNumber == {number}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=leftouter (
    SecurityAlert | summarize arg_max(TimeGenerated, *) by SystemAlertId
  ) on $left.AlertId == $right.SystemAlertId
| project IncidentNumber, Title, Severity, Status, Classification,
          IncidentTime = TimeGenerated, AlertName, AlertSeverity,
          Description, Entities, ExtendedProperties
| take 10
"""
    rows = _run(query)

    cleaned: list[dict[str, Any]] = []
    for row in rows:
        entities = _parse_entities(row.pop("Entities", None))
        details = _parse_custom_details(row.pop("ExtendedProperties", None))
        # The rule query itself is long and not evidence; drop it.
        row["entities"] = entities
        row["custom_details"] = details

        # Say plainly what can be correlated on. Some analytic rules emit no
        # usable identifiers at all, and without this the model tries anyway.
        usable = list(entities.get("ips", [])) + list(entities.get("accounts", []))
        for key in ("Email", "UserId", "SourceIP", "IPAddress"):
            value = details.get(key)
            if isinstance(value, str) and value and value not in usable:
                usable.append(value)
        row["usable_identifiers"] = usable

        # First row wins: an incident's rows differ only by linked alert.
        if _INCIDENT.get() is None:
            _INCIDENT.set(
                {
                    "number": row.get("IncidentNumber"),
                    "title": row.get("Title"),
                    "status": row.get("Status") or "Unknown",
                    "classification": row.get("Classification") or "",
                    "severity": row.get("Severity") or "",
                }
            )

        if not usable:
            unusable = entities.get("unusable_accounts", [])
            row["note"] = (
                "This incident carries no usable identifier: no source IP, and no "
                "account that is a real identifier"
                + (
                    f" (the account entity is {unusable!r}, which is an artefact of "
                    "the analytic rule's entity mapping, not a real account)"
                    if unusable
                    else ""
                )
                + ". Do not attempt to look these up and do not invent a substitute. "
                "Report that the incident lacks entity data, and say the detection "
                "rule's entity mapping should be fixed."
            )
        description = row.get("Description")
        if isinstance(description, str):
            row["Description"] = description[:600]
        cleaned.append(row)
    return cleaned


def get_related_alerts(entity: str, hours: int = MAX_HOURS, around: str | None = None,
                       hours_after: int = DEFAULT_HOURS_AFTER) -> list[dict[str, Any]]:
    """Sentinel alerts naming a given IP address or account."""
    value = str(entity or "").strip()
    if not value:
        raise ToolError("entity is required")
    try:
        value = str(ipaddress.ip_address(value))
    except ValueError:
        # This is a substring match against a JSON blob, so a short needle
        # matches almost every alert. "3" is not an entity.
        if not USER_PATTERN.match(value) or len(value) < 6:
            raise ToolError(
                "invalid entity: expected a full IP address, user id, or email "
                "address, not a fragment or a number taken from a field"
            )
    time_filter = _time_filter(
        _clean_anchor(around),
        _clean_hours(hours, MAX_HOURS),
        _clean_hours(hours_after, DEFAULT_HOURS_AFTER),
    )

    query = f"""
SecurityAlert
{time_filter}
| where Entities contains '{value}'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project TimeGenerated, AlertName, AlertSeverity, Status, Entities, ExtendedProperties
| order by TimeGenerated desc
| take {ALERT_MAX_ROWS}
"""
    rows = _run(query)
    for row in rows:
        row["entities"] = _parse_entities(row.pop("Entities", None))
        row["custom_details"] = _parse_custom_details(row.pop("ExtendedProperties", None))
    return rows


# --- Azure control plane ----------------------------------------------------

def get_azure_activity(
    caller: str | None = None,
    ip: str | None = None,
    resource: str | None = None,
    changes_only: bool = False,
    around: str | None = None,
    hours: int = DEFAULT_HOURS,
    hours_after: int = DEFAULT_HOURS_AFTER,
) -> list[dict[str, Any]]:
    """Azure control-plane operations: who changed which resource, and did it work.

    A different plane from application telemetry. Infrastructure alerts turn on two facts —
    *what resource was changed* and *who changed it* — so the projection leads
    with the caller and the fully qualified resource rather than an operation
    name alone.
    """
    time_filter = _time_filter(
        _clean_anchor(around),
        _clean_hours(hours),
        _clean_hours(hours_after, DEFAULT_HOURS_AFTER),
    )

    query = f"AzureActivity\n{time_filter}"
    if caller:
        query += f"\n| where Caller =~ '{_clean_user(caller)}'"
    if ip:
        query += f"\n| where CallerIpAddress == '{_clean_ip(ip)}'"
    if resource:
        query += f"\n| where _ResourceId contains '{_clean_resource(resource)}'"
    if changes_only:
        # Writes, deletes, and state-changing actions. Reads and list operations
        # are excluded only on request: key and credential listing is itself
        # security-relevant, so it is never hidden by default.
        # `contains`, not `has`: KQL's `has` matches whole tokens, so `!has 'LIST'`
        # happily lets LISTKEYS through.
        query += (
            "\n| where OperationNameValue contains 'WRITE'"
            " or OperationNameValue contains 'DELETE'"
            " or OperationNameValue contains 'ACTION'"
            "\n| where OperationNameValue !contains 'LIST'"
            " and OperationNameValue !contains 'READ'"
        )

    query += f"""
| extend ResourceName = tostring(split(_ResourceId, '/')[-1])
| extend ResourceType = strcat(tostring(split(_ResourceId, '/')[-3]), '/',
                               tostring(split(_ResourceId, '/')[-2]))
| project TimeGenerated, Caller, CallerIpAddress,
          Operation = OperationNameValue, Status = ActivityStatusValue,
          ResourceGroup, ResourceName, ResourceType, Level
| order by TimeGenerated desc
| take {MAX_ROWS}
"""
    return _run(query)


# --- tool registry ----------------------------------------------------------

TOOL_FUNCTIONS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "get_user_activity": get_user_activity,
    "get_ip_activity": get_ip_activity,
    "get_auth_events": get_auth_events,
    "get_related_requests": get_related_requests,
    "get_incident": get_incident,
    "get_related_alerts": get_related_alerts,
    "get_azure_activity": get_azure_activity,
}

# Schemas handed to the model. Descriptions matter: they are the only guidance
# the model gets about when a tool is worth calling.
TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_user_activity",
            "description": (
                "Return application security events for one user, identified by "
                "user id or email address. Use it to establish what a user did "
                "around the time of an alert, and whether the behaviour is unusual."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {
                        "type": "string",
                        "description": "User id or email address exactly as it appears in the alert.",
                    },
                    "hours": {
                        "type": "integer",
                        "description": f"Lookback window in hours (1-{MAX_HOURS}). Default {DEFAULT_HOURS}.",
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident. "
                            "Strongly preferred when investigating an incident: "
                            "without it the window runs backwards from now, which "
                            "finds nothing for anything older than a day."
                        ),
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": (
                            "Hours to include AFTER the anchor (default 6). Only "
                            "meaningful with 'around'. What happened next is often "
                            "the point."
                        ),
                    },
                },
                "required": ["user"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ip_activity",
            "description": (
                "Return application security events seen from one source IP "
                "address. Use it to check whether an IP is known, how many "
                "accounts it touched, and whether activity looks automated."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 or IPv6 address."},
                    "hours": {
                        "type": "integer",
                        "description": f"Lookback window in hours (1-{MAX_HOURS}). Default {DEFAULT_HOURS}.",
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident. "
                            "Strongly preferred when investigating an incident: "
                            "without it the window runs backwards from now, which "
                            "finds nothing for anything older than a day."
                        ),
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": (
                            "Hours to include AFTER the anchor (default 6). Only "
                            "meaningful with 'around'. What happened next is often "
                            "the point."
                        ),
                    },
                },
                "required": ["ip"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_auth_events",
            "description": (
                "Return authentication events: successful and failed logins and "
                "password resets. Omit the user to see the whole window, which is "
                "useful for spotting brute force or credential stuffing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {
                        "type": "string",
                        "description": "Optional user id or email to filter by.",
                    },
                    "hours": {
                        "type": "integer",
                        "description": f"Lookback window in hours (1-{MAX_HOURS}). Default {DEFAULT_HOURS}.",
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident. "
                            "Strongly preferred when investigating an incident: "
                            "without it the window runs backwards from now, which "
                            "finds nothing for anything older than a day."
                        ),
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": (
                            "Hours to include AFTER the anchor (default 6). Only "
                            "meaningful with 'around'. What happened next is often "
                            "the point."
                        ),
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_related_requests",
            "description": (
                "Return events recorded against one request path, e.g. "
                "/api/auth/refresh. Use it to see who else hit an endpoint "
                "involved in an alert."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Request path beginning with /.",
                    },
                    "hours": {
                        "type": "integer",
                        "description": f"Lookback window in hours (1-{MAX_HOURS}). Default {DEFAULT_HOURS}.",
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident. "
                            "Strongly preferred when investigating an incident: "
                            "without it the window runs backwards from now, which "
                            "finds nothing for anything older than a day."
                        ),
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": (
                            "Hours to include AFTER the anchor (default 6). Only "
                            "meaningful with 'around'. What happened next is often "
                            "the point."
                        ),
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident",
            "description": (
                "Return the full Sentinel incident by its number, including the "
                "entities its alerts identified (source IP addresses, accounts, "
                "URLs) and the analytic rule's custom details. Call this FIRST "
                "whenever the alert mentions an incident number: the Slack "
                "message often omits the source IP, and this is where it lives."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_number": {
                        "type": "integer",
                        "description": "Incident number, e.g. 136 for 'Incident #136'.",
                    },
                },
                "required": ["incident_number"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_related_alerts",
            "description": (
                "Return Sentinel alerts that named a given IP address or account. "
                "Use it to check whether an entity has appeared in other alerts, "
                "which distinguishes an isolated event from a pattern."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "entity": {
                        "type": "string",
                        "description": "An IP address, user id, or email address.",
                    },
                    "hours": {
                        "type": "integer",
                        "description": f"Lookback window in hours (1-{MAX_HOURS}).",
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident. "
                            "Strongly preferred when investigating an incident: "
                            "without it the window runs backwards from now, which "
                            "finds nothing for anything older than a day."
                        ),
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": (
                            "Hours to include AFTER the anchor (default 6). Only "
                            "meaningful with 'around'. What happened next is often "
                            "the point."
                        ),
                    },
                },
                "required": ["entity"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_azure_activity",
            "description": (
                "Return Azure control-plane operations from the Activity Log: who "
                "called which operation, on what resource, and whether it "
                "succeeded. Use this for alerts about Azure management activity - "
                "subscription-level operations, role assignments, snapshots, "
                "resource creation or deletion. The application event tools "
                "(get_user_activity, get_auth_events, get_related_requests) read "
                "application telemetry and know nothing about Azure management, so "
                "they return nothing for these alerts. Filter by caller and/or IP, "
                "or omit both to see everything in the window."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "caller": {
                        "type": "string",
                        "description": (
                            "Caller identity: a UPN such as "
                            "user@tenant.onmicrosoft.com, or a service principal "
                            "object id."
                        ),
                    },
                    "ip": {
                        "type": "string",
                        "description": "Caller IP address.",
                    },
                    "resource": {
                        "type": "string",
                        "description": (
                            "Resource name or resource-id fragment, e.g. "
                            "'example-api'. Use it to answer 'what else "
                            "happened to this resource'."
                        ),
                    },
                    "changes_only": {
                        "type": "boolean",
                        "description": (
                            "Exclude read and list operations, leaving writes, "
                            "deletes, and state changes. Use when the question is "
                            "what was CHANGED. Off by default, because credential "
                            "and key listing is itself security-relevant."
                        ),
                    },
                    "around": {
                        "type": "string",
                        "description": (
                            "Optional ISO-8601 timestamp to centre the window on, "
                            "e.g. the IncidentTime returned by get_incident."
                        ),
                    },
                    "hours": {
                        "type": "integer",
                        "description": f"Hours before the anchor (1-{MAX_HOURS}). Default {DEFAULT_HOURS}.",
                    },
                    "hours_after": {
                        "type": "integer",
                        "description": "Hours after the anchor. Default 6.",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
]


def dispatch(name: str, arguments: str) -> str:
    """Run one tool call on behalf of the model and return a JSON result string.

    Never raises: the model has to be told what went wrong so it can adapt or
    report the gap, and an exception here would abort an otherwise good
    investigation. Errors come back as data.
    """
    function = TOOL_FUNCTIONS.get(name)
    if function is None:
        return json.dumps({"error": f"unknown tool: {name}"})

    try:
        parsed = json.loads(arguments) if arguments else {}
        if not isinstance(parsed, dict):
            raise ValueError("arguments must be a JSON object")
    except ValueError as exc:
        return json.dumps({"error": f"could not parse arguments: {exc}"})

    # Drop anything not in the schema rather than passing it through.
    allowed = set(
        next(s["function"]["parameters"]["properties"] for s in TOOL_SPECS
             if s["function"]["name"] == name)
    )
    kwargs = {k: v for k, v in parsed.items() if k in allowed}

    token = _CURRENT_TOOL.set(name)
    try:
        rows = function(**kwargs)
    except ToolError as exc:
        logger.warning("tool %s rejected: %s", name, exc)
        return json.dumps({"error": str(exc)})
    except TypeError as exc:
        return json.dumps({"error": f"bad arguments for {name}: {exc}"})
    except Exception:
        logger.exception("tool %s failed unexpectedly", name)
        return json.dumps({"error": f"{name} failed"})
    finally:
        _CURRENT_TOOL.reset(token)

    logger.info("tool %s returned %d row(s)", name, len(rows))
    payload = json.dumps({"row_count": len(rows), "rows": rows}, default=str)
    if len(payload) <= MAX_RESULT_CHARS:
        return payload

    # Shed rows until it fits, and say so: a silently truncated result would be
    # read by the model as the complete picture.
    kept = list(rows)
    while kept and len(json.dumps({"rows": kept}, default=str)) > MAX_RESULT_CHARS:
        kept = kept[: len(kept) // 2 or 0]
    logger.warning("tool %s result truncated from %d to %d row(s)", name, len(rows), len(kept))
    return json.dumps(
        {
            "row_count": len(rows),
            "returned": len(kept),
            "truncated": True,
            "note": (
                f"Result too large; showing {len(kept)} of {len(rows)} rows. "
                "Narrow the window or use a more specific argument."
            ),
            "rows": kept,
        },
        default=str,
    )

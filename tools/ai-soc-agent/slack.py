"""Slack integration layer.

Everything Slack-specific lives here: request authentication, reading the alert
out of a thread, and rendering an analysis back into a threaded reply. `main.py`
owns the HTTP route; this module owns the protocol.

Security notes:
  * Every inbound request is authenticated with an HMAC signature before it is
    parsed. An unsigned or stale request is rejected outright.
  * The bot token is used only by this module. It is never shown to the LLM.
  * Message text from Slack is untrusted input and is passed to `llm.py` as
    evidence, never as instructions.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from typing import Any

import httpx

from llm import MAX_ALERT_CHARS, AlertAnalysis

logger = logging.getLogger(__name__)

SLACK_API = "https://slack.com/api"

# Slack signs with the literal version prefix "v0".
SIGNATURE_VERSION = "v0"
# Reject anything older than this to blunt replay attacks. Slack recommends 5 min.
MAX_REQUEST_AGE_SECONDS = 60 * 5

REQUEST_TIMEOUT_SECONDS = 15.0

# Slack rejects section blocks longer than 3000 characters.
MAX_BLOCK_CHARS = 2900

# Channel replies are for skimming. Tune these to taste; the complete analysis is
# always available from /analyze.
SUMMARY_CHARS = 260
ASSESSMENT_CHARS = 320
ITEM_CHARS = 110
EVIDENCE_ITEMS = 4
NEXT_ITEMS = 2
# Correlation queries are kept but capped; they are the one thing the incident
# link cannot give an analyst.
MAX_QUERIES_SHOWN = 3

VERDICT_DISPLAY = {
    "likely_malicious": (":rotating_light:", "LIKELY MALICIOUS"),
    "needs_investigation": (":mag:", "NEEDS INVESTIGATION"),
    "likely_benign": (":white_check_mark:", "LIKELY BENIGN"),
    "insufficient_evidence": (":grey_question:", "INSUFFICIENT EVIDENCE"),
}

SEVERITY_ICONS = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_blue_circle:",
    "unknown": ":grey_question:",
}


class SlackError(RuntimeError):
    """A Slack API call failed."""


class SlackConfigurationError(SlackError):
    """Required Slack configuration is missing from the environment."""


def get_signing_secret() -> str:
    secret = os.environ.get("SLACK_SIGNING_SECRET", "").strip()
    if not secret:
        raise SlackConfigurationError("missing environment variable: SLACK_SIGNING_SECRET")
    return secret


def get_bot_token() -> str:
    token = os.environ.get("SLACK_BOT_TOKEN", "").strip()
    if not token:
        raise SlackConfigurationError("missing environment variable: SLACK_BOT_TOKEN")
    return token


def is_configured() -> bool:
    """True when both Slack settings are present, without raising."""
    return bool(
        os.environ.get("SLACK_SIGNING_SECRET", "").strip()
        and os.environ.get("SLACK_BOT_TOKEN", "").strip()
    )


def verify_signature(body: bytes, timestamp: str, signature: str) -> bool:
    """Authenticate an inbound Slack request.

    Slack signs the raw request body, so `body` must be the exact bytes received —
    re-serialising the parsed JSON produces a different signature.
    """
    if not timestamp or not signature:
        return False

    try:
        age = abs(time.time() - int(timestamp))
    except ValueError:
        return False
    if age > MAX_REQUEST_AGE_SECONDS:
        logger.warning("rejected Slack request: timestamp %ss old", int(age))
        return False

    basestring = f"{SIGNATURE_VERSION}:{timestamp}:".encode() + body
    digest = hmac.new(
        get_signing_secret().encode(), basestring, hashlib.sha256
    ).hexdigest()
    expected = f"{SIGNATURE_VERSION}={digest}"

    # Constant-time comparison: a plain == leaks timing information.
    return hmac.compare_digest(expected, signature)


def strip_mention(text: str) -> str:
    """Remove the leading <@BOTID> token from an app_mention message."""
    cleaned = []
    for token in text.split():
        if token.startswith("<@") and token.endswith(">"):
            continue
        cleaned.append(token)
    return " ".join(cleaned).strip()


def _form_value(value: Any) -> str:
    """Render a value the way Slack's form-encoded API expects it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _call(method: str, payload: dict[str, Any], *, as_json: bool = True) -> dict[str, Any]:
    """POST to the Slack Web API and return the parsed body.

    Slack is not uniform about request encoding: write methods such as
    `chat.postMessage` accept a JSON body (needed for Block Kit), while read
    methods such as `conversations.replies` accept only form-encoded parameters
    and answer JSON with `invalid_arguments`. Callers pick with `as_json`.

    Slack also signals failure with `"ok": false` and HTTP 200, so the status
    code alone is not enough.
    """
    body: dict[str, Any] = (
        {"json": payload}
        if as_json
        else {"data": {k: _form_value(v) for k, v in payload.items()}}
    )
    try:
        response = httpx.post(
            f"{SLACK_API}/{method}",
            headers={"Authorization": f"Bearer {get_bot_token()}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
            **body,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        raise SlackError(f"{method} request failed: {type(exc).__name__}") from exc

    if not data.get("ok"):
        # Slack's error codes are safe to log; they name the problem, not secrets.
        raise SlackError(f"{method} returned error: {data.get('error', 'unknown')}")
    return data


def fetch_thread_parent(channel: str, thread_ts: str) -> str | None:
    """Return the text of the message that started a thread, if readable.

    That parent message is the alert itself when an analyst mentions the bot in
    reply to it. Requires channels:history (or groups:history for private
    channels); returns None rather than failing if the scope is missing.
    """
    try:
        data = _call(
            "conversations.replies",
            {"channel": channel, "ts": thread_ts, "limit": 1, "inclusive": True},
            as_json=False,
        )
    except SlackError as exc:
        logger.warning("could not read thread parent: %s", exc)
        return None

    messages = data.get("messages") or []
    if not messages:
        return None
    return message_text(messages[0]) or None


def _collect_text(node: Any, out: list[str]) -> None:
    """Recursively gather every string sitting under a "text" key.

    Block Kit is not one shape: `text` may be a plain string, an object with its
    own `text`, or nested several levels deep inside `elements` (rich_text) or
    `fields`. Walking the structure is more robust than enumerating the variants,
    which is what broke the first version of this.
    """
    if isinstance(node, dict):
        value = node.get("text")
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                out.append(stripped)
        for key, child in node.items():
            if key == "text" and isinstance(child, str):
                continue
            _collect_text(child, out)
    elif isinstance(node, list):
        for item in node:
            _collect_text(item, out)


def message_text(message: dict[str, Any]) -> str:
    """Extract everything readable from a Slack message.

    Alerts posted by an integration carry their detail in Block Kit; the
    top-level `text` field is only a one-line fallback for notifications. Reading
    just `text` would drop the fields the analysis actually needs.
    """
    parts: list[str] = []

    top = message.get("text")
    if isinstance(top, str) and top.strip():
        parts.append(top.strip())

    for block in message.get("blocks") or []:
        if not isinstance(block, dict):
            continue
        # `actions` blocks are buttons ("Triage in Defender", "Azure portal").
        # They are interface chrome, not evidence, and feeding them to the model
        # invites it to treat link text and run ids as facts about the alert.
        if block.get("type") == "actions":
            continue
        _collect_text(block, parts)

    # Attachments are the older format; some integrations still use them.
    for attachment in message.get("attachments") or []:
        if not isinstance(attachment, dict):
            continue
        for key in ("title", "text", "fallback"):
            value = attachment.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
        _collect_text(attachment.get("fields"), parts)

    # Preserve order while dropping the duplicates Block Kit fallbacks create.
    seen: set[str] = set()
    unique = [p for p in parts if not (p in seen or seen.add(p))]
    return "\n".join(unique).strip()


def resolve_alert_text(event: dict[str, Any]) -> str | None:
    """Work out what the analyst is asking us to analyse.

    Mentioned inside a thread, the alert is the thread's parent message and the
    mention text is treated as an extra instruction. Mentioned at top level, the
    mention text itself is the alert.
    """
    mention_text = strip_mention(event.get("text") or "")
    channel = event.get("channel") or ""
    thread_ts = event.get("thread_ts")
    event_ts = event.get("ts")

    parent_text = None
    if thread_ts and thread_ts != event_ts and channel:
        parent_text = fetch_thread_parent(channel, thread_ts)

    if parent_text and mention_text:
        combined = f"{parent_text}\n\nAnalyst note: {mention_text}"
    else:
        combined = parent_text or mention_text

    combined = (combined or "").strip()
    return combined[:MAX_ALERT_CHARS] or None


def _bullets(items: list[str], empty: str) -> str:
    if not items:
        return f"_{empty}_"
    text = "\n".join(f"• {item}" for item in items)
    return text[:MAX_BLOCK_CHARS]


def _trim(text: str, limit: int) -> str:
    """Shorten to a sentence boundary where possible, else hard-cut."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[:limit]
    stop = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: stop + 1] if stop > limit * 0.5 else cut.rstrip() + "…")


def _short_bullets(items: list[str], count: int, width: int) -> str:
    shown = [f"• {_trim(i, width)}" for i in items[:count]]
    if len(items) > count:
        shown.append(f"_+{len(items) - count} more_")
    return "\n".join(shown)


def build_analysis_blocks(analysis: AlertAnalysis) -> list[dict[str, Any]]:
    """Render the analysis as a short Slack reply.

    A channel reply has to be skimmable: severity, the few facts that matter,
    one line of judgement, the next step. The full report — every evidence item,
    the gaps, all recommendations — stays available from /analyze, so nothing is
    lost, it just is not pasted into the channel.
    """
    verdict = getattr(analysis, "verdict", "insufficient_evidence")
    icon, label = VERDICT_DISPLAY.get(verdict, VERDICT_DISPLAY["insufficient_evidence"])

    # Verdict leads. Severity is how bad it would be if real; the verdict is
    # whether anyone should do anything, and that is what a reader needs first.
    body = (
        f"{icon}  *{label}*  ·  {analysis.severity.upper()} severity  ·  "
        f"{analysis.confidence}% confidence\n"
        f"{_trim(analysis.summary, SUMMARY_CHARS)}"
    )

    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": body}}
    ]

    # Sentinel's own view of the incident. Worth its own line: an alert that is
    # already closed as a false positive needs a very different response from an
    # open one, and that should not depend on the model mentioning it.
    incident = getattr(analysis, "incident", None)
    if incident and incident.number:
        bits = [f"Incident #{incident.number}"]
        if incident.status:
            bits.append(f"*{incident.status}*")
        if incident.classification:
            bits.append(incident.classification)
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "  ·  ".join(bits)}],
            }
        )

    if analysis.observed_evidence:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Evidence*\n"
                    + _short_bullets(analysis.observed_evidence, EVIDENCE_ITEMS, ITEM_CHARS),
                },
            }
        )

    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Assessment* _(not fact)_\n"
                + _trim(analysis.assessment, ASSESSMENT_CHARS),
            },
        }
    )

    if analysis.recommended_investigation:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Next*\n"
                    + _short_bullets(analysis.recommended_investigation, NEXT_ITEMS, ITEM_CHARS),
                },
            }
        )

    blocks.extend(_query_blocks(analysis))

    # Gaps are counted rather than listed: useful as a confidence signal, rarely
    # worth reading line by line in a channel.
    footer = "AI triage — verify before acting."
    if analysis.missing_evidence:
        footer += f" {len(analysis.missing_evidence)} evidence gap(s) noted."
    footer += " Full report: POST /analyze."
    blocks.append(
        {"type": "context", "elements": [{"type": "mrkdwn", "text": footer}]}
    )
    return blocks


def _query_blocks(analysis: AlertAnalysis) -> list[dict[str, Any]]:
    """Render the queries the agent actually ran.

    This is the difference between an assertion and a citation: an analyst can
    paste these into Log Analytics and see the same rows the agent saw. Only
    queries we executed appear here — the model never writes KQL.
    """
    # The incident lookup is not worth showing: the alert already links to the
    # incident, and the portal shows it better than reproduced KQL would. What
    # is worth showing is the correlation work, which the incident page does not
    # give you: what else this IP or user did in a window around the event.
    # The full list, incident lookup included, still goes to /analyze callers.
    candidates = [q for q in analysis.queries if q.tool != "get_incident"]
    if not candidates:
        return []

    # Prefer the queries that actually found something; a channel reply has room
    # for a few, and "0 rows" queries are the least useful to re-run by hand.
    ranked = sorted(candidates, key=lambda q: q.row_count, reverse=True)
    shown = ranked[:MAX_QUERIES_SHOWN]

    lines: list[str] = []
    for record in shown:
        kql = " ".join(record.kql.split())  # collapse for a compact code block
        lines.append(f"// {record.tool} -> {record.row_count} row(s)\n{kql}")

    body = "\n\n".join(lines)
    if len(body) > MAX_BLOCK_CHARS - 100:
        body = body[: MAX_BLOCK_CHARS - 120] + "\n// ... truncated"

    label = "*Verify* _(Log Analytics)_"
    if len(candidates) > len(shown):
        label += f" — showing {len(shown)} of {len(candidates)}"

    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{label}\n```{body}```"},
        },
    ]


def post_thread_reply(
    channel: str,
    thread_ts: str,
    text: str,
    blocks: list[dict[str, Any]] | None = None,
) -> None:
    """Post a message into a thread.

    `text` is the notification/fallback string shown in sidebars and on devices
    that cannot render blocks, so it must stand on its own.
    """
    payload: dict[str, Any] = {
        "channel": channel,
        "thread_ts": thread_ts,
        "text": text,
    }
    if blocks:
        payload["blocks"] = blocks
    _call("chat.postMessage", payload)

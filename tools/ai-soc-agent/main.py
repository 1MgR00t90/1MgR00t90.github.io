"""FastAPI entrypoint for the security alert investigation agent.

This layer is deliberately thin: validate input, call the LLM layer, map failures
onto clean HTTP responses. It contains no provider-specific code.
"""

from __future__ import annotations

import logging
from collections import deque

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

import slack
from llm import (
    MAX_ALERT_CHARS,
    AlertAnalysis,
    LLMConfigurationError,
    LLMError,
    LLMRateLimitError,
    analyze_alert,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# The Azure SDK logs every request line, header name, and URL at INFO. That is
# noise in normal running and a liability in a security app, where the quieter
# the log the smaller the accidental-disclosure surface. Our own tool and event
# logging already records what was called and how many rows came back.
for _noisy in (
    "azure.core.pipeline.policies.http_logging_policy",
    "azure.identity",
    "azure.monitor",
    "httpx",
):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("security-alert-agent")

app = FastAPI(
    title="Security Alert Agent",
    description="Evidence-based triage of application-security alerts.",
    version="0.2.0",
)

# Slack retries an event if we fail to ack in time, and a retry that arrives while
# the first is still running would double-post. This remembers recently handled
# event ids. It is per-replica and in-memory on purpose: Slack retries reach the
# same app within seconds, and a durable store is not worth a dependency yet.
_SEEN_EVENT_IDS: deque[str] = deque(maxlen=500)


class HealthResponse(BaseModel):
    status: str


class AnalyzeRequest(BaseModel):
    """One security alert, as free text."""

    alert: str = Field(min_length=1, max_length=MAX_ALERT_CHARS)


@app.get("/", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness probe. Does not touch the model, so it stays free and fast."""
    return HealthResponse(status="ok")


@app.post("/analyze", response_model=AlertAnalysis)
def analyze(request: AnalyzeRequest) -> AlertAnalysis:
    """Analyse a single alert and return a structured, evidence-based assessment."""
    try:
        return analyze_alert(request.alert)
    except LLMConfigurationError:
        # Logged with detail, reported without it: the message names env vars.
        logger.exception("LLM is not configured")
        raise HTTPException(status_code=503, detail="Analysis service is not configured.")
    except LLMRateLimitError:
        logger.warning("rate limited by Azure OpenAI")
        raise HTTPException(
            status_code=429, detail="Rate limit reached. Retry shortly."
        )
    except LLMError:
        logger.exception("LLM call failed")
        raise HTTPException(status_code=502, detail="Analysis service is unavailable.")
    except Exception:
        logger.exception("Unexpected failure during analysis")
        raise HTTPException(status_code=500, detail="Internal error.")


def _handle_mention(channel: str, thread_ts: str, event: dict) -> None:
    """Work out what to analyse, analyse it, and post the result to its thread.

    Runs after the HTTP response has been sent, so nothing here can make Slack
    time out or retry. Reading the thread parent is a Slack API round trip and
    belongs here rather than in the ack path. Every failure is reported into the
    thread: a silent bot looks identical to a broken one.
    """
    try:
        alert_text = slack.resolve_alert_text(event)
    except Exception:
        logger.exception("Could not resolve alert text from Slack event")
        _try_reply(channel, thread_ts, "Could not read the alert from this thread.")
        return

    if not alert_text:
        _try_reply(
            channel,
            thread_ts,
            "Mention me in a reply to an alert, or include the alert text with the mention.",
        )
        return

    logger.info("analysing %d chars for channel=%s thread=%s",
                len(alert_text), channel, thread_ts)
    try:
        analysis = analyze_alert(alert_text)
    except LLMConfigurationError:
        logger.exception("LLM is not configured")
        _try_reply(channel, thread_ts, "Analysis service is not configured.")
        return
    except LLMRateLimitError:
        logger.warning("rate limited by Azure OpenAI")
        _try_reply(
            channel,
            thread_ts,
            "Hit the Azure OpenAI rate limit for this deployment before the "
            "analysis finished. Nothing is wrong with the alert - mention me "
            "again in a minute and I will retry.",
        )
        return
    except Exception:
        logger.exception("Analysis failed for Slack mention")
        _try_reply(channel, thread_ts, "Analysis failed. Check the service logs.")
        return

    fallback = (f"{analysis.verdict.replace('_', ' ').title()} — "
                f"{analysis.severity} severity, {analysis.confidence}%: {analysis.summary}")
    try:
        slack.post_thread_reply(
            channel, thread_ts, fallback, slack.build_analysis_blocks(analysis)
        )
    except slack.SlackError:
        logger.exception("Could not post analysis to Slack")


def _try_reply(channel: str, thread_ts: str, text: str) -> None:
    """Best-effort error notice; never raises out of a background task."""
    try:
        slack.post_thread_reply(channel, thread_ts, text)
    except slack.SlackError:
        logger.exception("Could not post error notice to Slack")


@app.post("/slack/events")
async def slack_events(request: Request, background: BackgroundTasks) -> Response:
    """Slack Events API endpoint.

    Slack requires a 2xx within 3 seconds, and analysis takes longer than that, so
    this authenticates the request, decides whether to act, and hands the work to
    a background task before returning.
    """
    # The signature covers the raw bytes, so read the body before parsing.
    body = await request.body()

    if not slack.is_configured():
        logger.error("Slack request received but Slack is not configured")
        raise HTTPException(status_code=503, detail="Slack integration is not configured.")

    if not slack.verify_signature(
        body,
        request.headers.get("X-Slack-Request-Timestamp", ""),
        request.headers.get("X-Slack-Signature", ""),
    ):
        # Unauthenticated: do not parse the body, do not explain why.
        logger.warning("rejected Slack request with invalid signature")
        raise HTTPException(status_code=401, detail="Invalid signature.")

    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed request body.")

    # One-time endpoint verification when the Request URL is saved in Slack.
    if payload.get("type") == "url_verification":
        logger.info("Slack url_verification challenge answered")
        return Response(content=payload.get("challenge", ""), media_type="text/plain")

    # Log the shape of every accepted event, never its text: message bodies carry
    # alert contents and user identifiers that do not belong in logs.
    _event_preview = payload.get("event") or {}
    logger.info(
        "Slack event received: payload_type=%s event_type=%s subtype=%s "
        "channel=%s has_thread=%s from_bot=%s",
        payload.get("type"),
        _event_preview.get("type"),
        _event_preview.get("subtype"),
        _event_preview.get("channel"),
        bool(_event_preview.get("thread_ts")),
        bool(_event_preview.get("bot_id")),
    )

    # A retry means our earlier ack was late; the original is likely still running.
    if request.headers.get("X-Slack-Retry-Num"):
        logger.info("ignoring Slack retry %s", request.headers["X-Slack-Retry-Num"])
        return Response(status_code=200)

    event_id = payload.get("event_id")
    if event_id:
        if event_id in _SEEN_EVENT_IDS:
            logger.info("ignoring duplicate event %s", event_id)
            return Response(status_code=200)
        _SEEN_EVENT_IDS.append(event_id)

    event = payload.get("event") or {}

    # Ignore anything the bot itself posted, or this would answer its own replies.
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        logger.info("ignoring bot-authored message")
        return Response(status_code=200)

    if event.get("type") != "app_mention":
        logger.info("ignoring event of type %s (only app_mention is handled)",
                    event.get("type"))
        return Response(status_code=200)

    channel = event.get("channel")
    # Reply into the existing thread, or start one on the mentioned message.
    thread_ts = event.get("thread_ts") or event.get("ts")
    if not channel or not thread_ts:
        logger.warning("app_mention without channel or ts; cannot reply")
        return Response(status_code=200)

    # Everything else — reading the thread, calling the model, posting back —
    # happens after this response, so the ack always lands well inside 3 seconds.
    logger.info("queued analysis for channel=%s thread=%s", channel, thread_ts)
    background.add_task(_handle_mention, channel, thread_ts, event)
    return Response(status_code=200)

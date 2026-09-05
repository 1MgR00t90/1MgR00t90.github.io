# AI SOC Agent

An LLM security-alert investigation agent that runs on Azure Container Apps, is invoked from
Slack, and gathers its own evidence from Log Analytics through a fixed set of read-only tools.

An analyst replies `@agent` to an alert in Slack. The agent reads the alert, looks up the
incident in Microsoft Sentinel, pulls the entities it names, correlates them against application
and Azure control-plane telemetry, and answers in the thread with a short triage — separating
what it **observed** from what it **concluded**, and showing the queries it ran so a human can
reproduce them.

The design rule everything else follows: **the model never receives Azure credentials, never
writes KQL, and never executes anything.** It chooses from a fixed set of parameterised tools;
this codebase owns every query.

---

## The pipeline

```text
Sentinel analytic rule fires
        │
        ▼
Logic App playbook ──────────────► Slack channel  (alert with Custom Details)
                                        │
                          analyst replies "@agent take a look"
                                        │
                                        ▼
                         POST /slack/events   (HMAC-signed by Slack)
                                        │
                   verify signature → ack 200 within 3s → hand off
                                        │
                                        ▼
                        ┌──────── background task ────────┐
                        │  read the alert from the thread │
                        │  ask the model what to look up  │
                        │  run constrained read-only KQL  │  ◄── Managed Identity
                        │  validate the model's answer    │      (Log Analytics Reader)
                        └────────────────┬────────────────┘
                                         ▼
                            threaded reply in Slack
```

Azure Container Apps runs at **min-replicas 0**, so the agent costs nothing until an alert is
actually mentioned.

## Repository layout

| File | Responsibility |
| ---- | -------------- |
| `main.py` | FastAPI app: health, `/analyze`, `/slack/events`. HTTP concerns only. |
| `llm.py` | The model provider, the system prompt, the response schema, and the bounded tool-calling loop. The only file that knows which LLM is in use. |
| `slack.py` | Request authentication, reading an alert out of a thread, Block Kit rendering. |
| `tools.py` | The read-only investigation tools. Owns every KQL query and validates every argument. |
| `docs/sentinel-rules.md` | The detection-engineering side: what an alert must carry for an agent to be able to investigate it. |

Four modules, ~1,300 lines, no framework beyond FastAPI. Deliberately: every component should be
explainable in an interview without hand-waving at an abstraction layer.

---

## Security model

This is the part worth reading.

### 1. The model never writes KQL

It picks a tool name and supplies typed arguments. Every query is a fixed template in `tools.py`.
There is no code path that sends model-authored text to a query engine.

### 2. Arguments are validated against allowlists, not escaped

```python
USER_PATTERN = re.compile(r"^[A-Za-z0-9._@+\-]{3,128}$")
PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._/~\-]{0,255}$")
# an IP must parse as an IP; a timestamp is parsed to a datetime and re-serialised by us
```

Anything that fails is **refused**, not escaped and hoped for. Escaping is the approach that
eventually fails; refusing is the one that doesn't. The test suite fires KQL injection at every
tool — `x' or 1==1 //`, `1.1.1.1' | union AppEvents //`, `'; SecurityAlert | take 100 //` — and
asserts every one is rejected before a query is built.

This is not theoretical. In production the model once tried to look up an "IP address" it had
assembled from digits in a workflow run id in the alert footer. `ipaddress.ip_address()` refused
to parse it, the tool returned an error instead of a query, and the analysis reported the gap
honestly. The guardrail fired on a real alert within hours of going live.

### 3. Read-only credentials, no keys

Data access uses the container's **system-assigned Managed Identity** holding
`Log Analytics Reader` on a single workspace. No connection string, no key, nothing in the
container that can write. The Azure OpenAI key is a Container Apps **secret reference**, never a
plain environment value.

### 4. Untrusted input is treated as untrusted

Alert text originates from logs and chat, which means an attacker can influence it. It is fenced
in `<alert>` tags, labelled as data, and the system prompt instructs the model to *report*
embedded instructions as a possible prompt-injection attempt rather than obey them.

### 5. Model output is not trusted either

Responses are constrained by a strict JSON schema on the way out and re-validated with Pydantic
on the way in. Malformed output is an error, not something to paper over.

### 6. Everything is bounded

| Bound | Value | Why |
| ----- | ----- | --- |
| Alert text | 8,000 chars | caps prompt size |
| Model output | 2,500 tokens | includes reasoning tokens |
| Tool rounds | 4, then tools are withdrawn | an agent that can call tools can loop forever |
| Rows per query | 50 (15 for alert tables) | alert rows carry whole JSON blobs |
| Tool result | 12,000 chars, sheds rows to fit | tool output feeds the next prompt |
| Query window | 7 days either side of the anchor | bounds scan cost |

The tool-result cap exists because of a real incident: a weak validator accepted a one-character
"identifier", the resulting substring match hit nearly every row, and the oversized result blew
the deployment's tokens-per-minute quota on the next call. Truncation is now explicit — the model
is told the result was shortened, because a silently truncated result reads as a complete one.

### 7. Nothing can change state

Every tool is a read. The agent proposes; a human decides. Containment actions are deliberately
out of scope until there is a human-approval step.

---

## Investigation tools

| Tool | Answers |
| ---- | ------- |
| `get_incident(number)` | What did Sentinel record — including the source IP, account and URL entities the chat message usually omits? |
| `get_user_activity(user, …)` | What has this user been doing? |
| `get_ip_activity(ip, …)` | What has this source IP been doing, and to how many accounts? |
| `get_auth_events(user?, …)` | Logins, failures, password resets. |
| `get_related_requests(path, …)` | Who else hit this endpoint? |
| `get_related_alerts(entity, …)` | Has this IP or account appeared in other alerts? |
| `get_azure_activity(caller, ip, resource, changes_only, …)` | Which resource was changed, by whom, from where, and did it succeed? |

### Two planes, and why it matters

The first five read application telemetry (custom security events emitted by the app). The last
reads `AzureActivity`, the Azure control plane. **Using the wrong one returns zero rows, and zero
rows reads as "nothing suspicious happened."**

That is the most dangerous failure mode in a tool like this — an empty result is exculpatory
unless you know it means *wrong data source*. The system prompt states the distinction
explicitly, and the tool descriptions say which alerts each plane answers.

### Windows are anchored to the incident, not to now

Every tool takes an optional `around` (ISO-8601) plus `hours_after`:

```python
get_ip_activity("203.0.113.9", hours=24)                      # → 0 rows for a week-old incident
get_ip_activity("203.0.113.9", around=IncidentTime, hours=24)  # → the attack itself
```

`get_incident` returns `IncidentTime` and the prompt threads it through. `hours_after` matters
independently: **what happened after an attempt is usually what decides whether it succeeded.**

### Credential reads are not filtered out by default

`changes_only` drops read and list operations, but it is **off** by default. Azure classifies
`listKeys`, `listCredentials` and `listPublishingCredentials` as *reads* — yet what they read is
a secret. An attacker enumerating keys writes nothing, so any view filtered to changes shows a
quiet day. That default is a deliberate choice, and the tool description says why.

---

## Showing its working

Every response carries a `queries` array — the tool, the exact KQL executed, and the row count —
and the Slack reply ends with a copy-pasteable block:

```text
Verify (Log Analytics)
// get_ip_activity -> 3 row(s)
AppEvents | where TimeGenerated between (datetime(...) .. datetime(...)) | ...
```

The evidence/conclusion split only means something if a human can check the evidence, and they
can only check it if they can see where it came from.

`queries` is **absent from the JSON schema the model answers** — it is populated by the
application after validation, from a context-local log written as each query executes. The agent
reports queries it *ran*, never queries it *imagined*. The incident lookup is omitted from the
Slack block because the alert already links to the incident; only the correlation work is shown.

The agent never writes KQL for a human to run either. A plausible query against a hallucinated
column returns zero rows, and an analyst reads that as "no evidence found" — a worse failure than
offering nothing, because it manufactures false confidence in the direction of under-reacting.

---

## Configuration

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `AZURE_OPENAI_BASE_URL` | yes | OpenAI-compatible v1 endpoint, e.g. `https://<resource>.openai.azure.com/openai/v1/` |
| `AZURE_OPENAI_API_KEY` | yes | Store as a Container Apps secret, not a plain value |
| `AZURE_OPENAI_MODEL` | no | The **deployment** name, not the base model name |
| `SLACK_SIGNING_SECRET` | for Slack | Authenticates inbound events |
| `SLACK_BOT_TOKEN` | for Slack | `xoxb-…`; reads thread parents and posts replies |
| `AZURE_LOG_ANALYTICS_WORKSPACE_ID` | for tools | Workspace GUID. Auth is Managed Identity — no accompanying secret |

Configuration is read lazily, so a container with missing configuration still starts and still
passes health checks; it answers `/analyze` with `503` rather than crash-looping.

### Telemetry schema

Applications instrument themselves differently, so the table and field names the investigation
tools read are configuration rather than assumptions. The defaults describe an application writing
security events to Application Insights `AppEvents` with the detail in a `Properties` JSON column;
point them at your own schema and every tool follows.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `TELEMETRY_TABLE` | `AppEvents` | Table holding application security events |
| `TELEMETRY_PROPERTIES` | `Properties` | Column holding event detail as JSON |
| `TELEMETRY_FIELD_USER` | `userId` | Property naming the acting user |
| `TELEMETRY_FIELD_EMAIL` | `email` | Property naming the user's email |
| `TELEMETRY_FIELD_IP` | `ipAddress` | Property naming the source address |
| `TELEMETRY_FIELD_PATH` | `path` | Property naming the request path |
| `TELEMETRY_FIELD_METHOD` | `method` | Property naming the HTTP method |
| `TELEMETRY_FIELD_SEVERITY` | `severity` | Property naming the event severity |
| `TELEMETRY_FIELD_USER_AGENT` | `userAgent` | Property naming the user agent |
| `PLATFORM_USER_AGENTS` | `Edge Functions,Lambda,node-fetch,axios,undici` | Agents indicating a server-side caller |

`PLATFORM_USER_AGENTS` drives the `IpProvenance` annotation. Server-side handlers record the
platform's egress address rather than the caller's, and without naming that distinction a handful
of rotating cloud IPs reads as a handful of distinct clients.

These values are interpolated into KQL, so each is validated against a strict identifier pattern at
import. A malformed value fails loudly at startup rather than building a broken — or attacker-shaped
— query.

## Running it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill in, then export
uvicorn main:app --reload --port 8000
```

```bash
curl -X POST localhost:8000/analyze -H 'Content-Type: application/json' \
  -d '{"alert":"Possible refresh token reuse. User: user-123. Source IP: 203.0.113.9. Path: /api/auth/refresh."}'
```

## Deploying

```bash
az containerapp up --name soc-agent -g <rg> --source . \
  --ingress external --target-port 8000

az containerapp secret set -n soc-agent -g <rg> \
  --secrets openai-key=<key> slack-signing-secret=<secret> slack-bot-token=<token>

az containerapp update -n soc-agent -g <rg> --min-replicas 0 \
  --set-env-vars AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com/openai/v1/ \
                 AZURE_OPENAI_API_KEY=secretref:openai-key \
                 SLACK_SIGNING_SECRET=secretref:slack-signing-secret \
                 SLACK_BOT_TOKEN=secretref:slack-bot-token \
                 AZURE_LOG_ANALYTICS_WORKSPACE_ID=<workspace-guid>
```

Then grant the identity read access to the workspace:

```bash
MI=$(az containerapp show -n soc-agent -g <rg> --query identity.principalId -o tsv)
az role assignment create --assignee-object-id $MI --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" --scope <workspace-resource-id>
```

**Slack app:** bot scopes `app_mentions:read`, `chat:write`, and `channels:history` (or
`groups:history` for private channels). Subscribe to the bot event **`app_mention`**, set the
Request URL to `https://<host>/slack/events`, and invite the bot to the channel.

> Slack's **Socket Mode must be off.** With it on, Slack delivers events over a WebSocket and
> never calls the Request URL — the page still shows "Verified" and the events list still looks
> correct, so it presents as "the bot receives nothing" with no error anywhere. Socket Mode also
> needs a process holding a persistent connection, which is incompatible with scale-to-zero.

---

## Cost

Measured, not estimated: **~11,300 tokens per fully-tooled investigation** (3 model calls, ~88%
input, since each tool round re-sends the accumulated conversation).

At ~25 alerts/month that is well under a dollar of inference. The dominant fixed cost in a
minimal deployment is the container registry; the app itself sits inside the Container Apps free
grant because it scales to zero.

Deliberate design consequence: **the agent costs nothing when nobody asks it anything.** Watching
a channel and auto-analysing every alert is possible but was rejected — it needs broader Slack
scopes (the bot receives every human message, not just alerts), and a human deciding "this one is
worth a look" is a real filter.

---

## Engineering notes

Things that only show up against real data, kept here because they are the interesting part:

- **An empty result is not evidence of absence.** Querying application logs for an Azure admin
  returns zero rows and reads as reassuring. Naming the two planes explicitly in the prompt was
  the fix.
- **Anchoring beats widening.** A week-old incident has no activity "in the last 24 hours". The
  instinct is to widen the lookback; the correct fix is to anchor the window to the incident.
- **Detections must carry entities.** An alert that says "repeated failures from a single source
  IP" without *naming* the IP cannot be investigated by anything, human or agent. Half the value
  of this project came from fixing the analytic rules — see `docs/sentinel-rules.md`.
- **Rules can be silently dead.** Several detections queried tables with zero rows because the
  connector was never enabled. They had never fired and never would; nothing surfaced that.
- **`has` is token-based in KQL.** `!has 'LIST'` does not exclude `LISTKEYS`. Use `contains`.
- **GPT-5-family models** require `max_completion_tokens` instead of `max_tokens` and reject a
  non-default `temperature`; the token budget includes reasoning tokens.
- **Slack's API is not uniform.** `chat.postMessage` accepts JSON (needed for Block Kit); read
  methods like `conversations.replies` accept only form encoding and answer JSON with
  `invalid_arguments`.
- **Block Kit is not one shape.** A block's `text` may be a string, an object, or nested several
  levels down inside `elements`. Walking the structure beats enumerating the variants.

## Limitations

- `/analyze` is unauthenticated — `/slack/events` verifies Slack signatures, but put auth in
  front of `/analyze` before exposing the host.
- Deduplication of Slack retries is per-replica and in-memory.
- Tool use is the model's judgement; it sometimes answers from the alert alone.
- Analysis quality is bounded by what the detection rules emit. A vague alert produces a vague
  answer — correctly, but not usefully.

## Roadmap

Human-in-the-loop containment: any action that *changes* state — revoking a token, disabling an
account, blocking an IP — behind explicit approval in Slack. The agent proposes; a person decides.
Everything today is read-only, which is the right place to pause.

## Licence

MIT.

# Detection engineering: what an alert must carry

Half the value of this project was not in the agent. It was in discovering that the alerts
themselves could not be investigated — by an agent or by a human.

This document covers what a Sentinel analytic rule has to emit for downstream automation to work,
and the failure patterns worth checking in any environment.

---

## The chain

```text
Analytic rule
  ├── query          → the columns everything downstream can use
  ├── entity mapping → Account / IP / AzureResource on the incident
  └── custom details → arbitrary key/value pairs on the alert
        │
        ▼
Logic App playbook renders custom details generically:

    Custom_Details = alert additionalData['Custom Details']
    Details_Pairs  = Select → "• *Key:* value" per entry
    Details_Block  = joined under "*Details*"
        │
        ▼
Slack message                     Agent's get_incident()
                                    → unpacks entities + custom details
```

**The useful consequence:** if the playbook renders custom details generically, adding custom
details to a rule improves both the chat message *and* the agent's evidence, with no code or
playbook change. One edit, two consumers.

---

## Failure pattern 1 — the alert describes a category, not an event

A rule fires on "rare subscription-level operations", and the message says exactly that: a
paragraph of template prose about what the rule detects in general. It does not say which
operation, which resource, or who.

An analyst cannot triage it. Neither can an agent: with no entity to pivot on, the model either
reports nothing useful or — worse — reaches for something that *looks* like an identifier
elsewhere in the message.

**Fix:** map the query's columns into Custom Details. Most template rules already project
everything needed; they simply never surface it.

```
Resource       → ResourceName
ResourceType   → ResourceType
ResourceGroup  → ResourceGroup
Operation      → OperationNameValue
Result         → ActivityStatusValue
Caller         → Caller
```

For an infrastructure alert, two facts decide everything: **which resource was changed, and who
changed it.** An alert missing either is not actionable.

Custom Details keys should be single words if the playbook builds them into XML — spaces break
element names.

---

## Failure pattern 2 — the query discards what you need

Some rules aggregate before they project, dropping the resource id in a `summarize` and leaving
nothing to map. Worth reading the query before assuming a field is unavailable — and equally
worth reading it before assuming it is *not*.

In one case a rule already produced `ResourceIds = make_list(_ResourceId)` and nobody had ever
mapped it. The data had been in every alert for months and had never reached anyone. The fix was
two lines to expose a scalar for entity mapping:

```kql
| extend PrimaryResourceId = tostring(ResourceIds[0])
| extend PrimaryResource = tostring(split(PrimaryResourceId, '/')[-1])
```

**Check what the rule already emits before writing new KQL.**

---

## Failure pattern 3 — broken entity mapping

An entity is recorded, so the incident *looks* populated, but the mapped column is wrong:

```json
[{"$id":"3","Name":"3","IsDomainJoined":false,"Type":"account","AccountName":"3"}]
```

Sentinel faithfully records "the account involved was `3`". Downstream, an agent faithfully looks
up a user called `3`, and entity-based correlation and UEBA silently do nothing.

Worth auditing periodically:

```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| mv-expand E = parse_json(Entities)
| where tostring(E.Type) == "account"
| extend Acct = coalesce(tostring(E.UserPrincipalName), tostring(E.DisplayName), tostring(E.AccountName))
| extend Broken = (strlen(Acct) < 6 or Acct matches regex "^[0-9]+$")
| summarize Alerts = dcount(SystemAlertId) by Broken, AlertName
```

Defensively, consumers should treat a degenerate identifier as *absent* and say so, rather than
passing it on:

```python
def _is_usable_account(value: str) -> bool:
    return len(value) >= 6 and not value.isdigit()
```

---

## Failure pattern 4 — rules that can never fire

A rule querying a table with no data is not a quiet rule; it is a **gap that looks like
coverage**. It appears in the rule list, shows enabled, and reports nothing forever.

```kql
union isfuzzy=true withsource=T
    SigninLogs, OfficeActivity, AzureDiagnostics, AuditLogs, AzureActivity
| where TimeGenerated > ago(30d)
| summarize Rows = count() by T
```

Any table your rules reference that is missing from those results is a dead detection. In one
audit, five of eleven rules queried tables whose connectors had never been enabled.

Related: read the logic, not just the name. One rule named for impossible-travel detection
projected every successful sign-in with no distance calculation, no time comparison, and no
threshold. Had its connector been enabled it would have alerted on every login.

---

## Failure pattern 5 — matching that does not match

`has` and `has_any` in KQL match whole terms, not substrings:

```kql
| where OperationNameValue !has "LIST"       // does NOT exclude LISTKEYS
| where OperationNameValue !contains "LIST"  // does
```

The inverse mistake is worse. Widening a rule's operation list to "catch more" can silently
convert it into a noise generator — in one case a proposed widening would have alerted on the
cloud platform registering its own first-party service principals, roughly 24 times a month.
**Check what the widened match actually returns before shipping it.**

---

## Writing a new rule: derive thresholds from data

Detection thresholds should come from your own telemetry, not from intuition. The method:

**1. Establish the operation set.** For credential enumeration, the interesting operations are
the ones Azure classifies as *reads* but which return secrets:

```
listKeys · listCredentials · listSecrets · listAccountSas · listServiceSas
listConnectionStrings · listAdminKeys · listQueryKeys · listPublishingCredentials
```

Anything filtered to writes will never show these. An attacker enumerating keys modifies nothing.

**2. Profile the normal.** Group by actor and time bucket, and look at the maxima:

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any (CredentialOps)
| summarize Ops = count(), Resources = dcount(_ResourceId)
        by Caller, bin(TimeGenerated, 1h)
| summarize MaxOpsPerHour = max(Ops), MaxResourcesPerHour = max(Resources) by Caller
```

**3. Identify the service identities** that dominate the volume and exclude them by principal id,
not by operation — excluding the operation blinds the rule.

**4. Choose the breadth signal over the volume signal.** `dcount(resource)` captures enumeration
(touching many things) better than raw count (touching one thing repeatedly, which is usually
automation). Keep a volume threshold as a backstop.

**5. Backtest before enabling.** Run the finished rule over 30 days with the scheduling window
simulated as a bin:

```kql
| summarize … by Actor, bin(TimeGenerated, 1h)
| where ResourceCount >= <breadth> or OpCount >= <volume>
```

If it would have fired hundreds of times, it is a noise generator. A handful of hits over a month
— each one you would genuinely want to look at — is the target. Tune the thresholds until that is
true, then enable.

**6. Do not allowlist your admins.** An administrator enumerating keys is exactly the behaviour
worth surfacing. Correct thresholds keep the rule quiet without creating a blind spot that
matches an attacker's most likely path.

---

## Checklist

- [ ] Does the alert name the resource and the identity?
- [ ] Are entities mapped, and do they contain real identifiers?
- [ ] Are custom details mapped, with single-word keys?
- [ ] Does the source table actually have data?
- [ ] Does the query logic implement what the rule name claims?
- [ ] Was the threshold backtested over real history?
- [ ] Are read-but-sensitive operations in scope, or only writes?

# Scenario 07: scheduled task persistence (T1053.005)

## The attack

Created a scheduled task that re-launches a program every five minutes, registered to run as SYSTEM — a step up from the registry Run key in scenario 05, since SYSTEM-level execution gives it privileges the logged-in user never had.

```cmd
schtasks /create /sc minute /mo 5 /tn "SystemCheck" /tr "C:\Users\Public\update.exe" /ru SYSTEM
```

## The gap

Nothing in Sysmon logs scheduled-task creation — there's no Sysmon event ID for it. Windows tracks it in two other places instead, and neither is guaranteed to be on by default:

- **Security Event 4698** ("A scheduled task was created"), which needs an advanced audit policy most systems don't have enabled.
- **Task Scheduler's own Operational log** (Event ID 106, "User registered Task Scheduler task"), a separate event channel that exists but is commonly left disabled.

Checked the agent's `ossec.conf` and confirmed the Task Scheduler channel wasn't in the list of channels being collected at all — so there was nothing for Wazuh to even see.

## The fix, part one: getting the data flowing

Enabled the channel in Event Viewer (`Applications and Services Logs → Microsoft → Windows → Task Scheduler → Operational → Enable Log`), then added it to the agent's config:

```xml
<localfile>
  <location>Microsoft-Windows-TaskScheduler/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restarted the Wazuh agent service, recreated the task, and this time Wazuh actually had something to work with.

## The fix, part two: the detection wasn't as missing as it looked

Once the channel was flowing, a default Wazuh rule did fire — rule 67014, level 3, description: `Task Scheduler: .`

That's not a gap in coverage after all. Wazuh ships a rule specifically for this event (`0955-WEF-baseline_rules.xml`, rule 67014, matching `providerName: Microsoft-Windows-TaskScheduler` and `eventID: 106`), complete with the correct MITRE T1053.005 mapping. It's just broken: the description template references `$(win.eventdata.message)`, a field that doesn't carry the task name, so it renders as a blank period instead of anything useful. Low severity, no detail — technically "detected," practically useless.

So the real work was building something more informative on top, not building detection from nothing.

## Building a better rule, and why it didn't work the first few times

Wrote two custom rules: a base rule that pulls the actual task name into the description, and an escalated one that triggers specifically when the task runs as SYSTEM (SID `S-1-5-18`, a fixed well-known identifier, not something that varies per machine):

```xml
<rule id="100110" level="6">
  <if_sid>60009</if_sid>
  <field name="win.system.providerName">Microsoft-Windows-TaskScheduler</field>
  <field name="win.system.eventID">106</field>
  <description>Scheduled task registered: $(win.eventdata.taskName)</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>persistence,</group>
</rule>

<rule id="100111" level="10">
  <if_sid>100110</if_sid>
  <field name="win.eventdata.userContext">^S-1-5-18$</field>
  <description>Scheduled task registered to run as SYSTEM: $(win.eventdata.taskName) - possible persistence or privilege escalation</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>persistence,privilege_escalation,</group>
</rule>
```

The first version of this rule tested correctly in `wazuh-logtest` against a reconstructed copy of the real event, fields and all, and then did nothing at all once deployed live. Nothing in the dashboard, not even a failed match — it was as if the rule didn't exist.

The cause turned out to be more interesting than a typo: `wazuh-logtest` had decoded the test input using Wazuh's generic `json` decoder, but the live agent's event was coming through a different, more specific decoder, `windows_eventchannel`. Both expose the same field names, so the data looked identical either way. The real difference was structural. Wazuh's own working rule (67014) isn't a standalone rule — it's chained underneath a parent rule, `<if_sid>60009</if_sid>`, which is what actually gets tested against incoming Windows events first. Only logs that already matched that parent get checked against its children. My rule had no such anchor, so it was never in the running for this category of log at all, regardless of how correct its field matching was.

Finding that meant going straight to the source — grepping the installed ruleset for rule 67014's actual definition rather than guessing — and copying the same `if_sid: 60009` chain into the custom rule. That was the fix. Confirmed afterward with a fresh scheduled-task creation and a direct dashboard search for the new rule IDs.

## Verifying it

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Useful for checking a rule's field-matching logic in isolation, but not sufficient on its own for this one — a rule that passes `wazuh-logtest` can still fail to fire live if it isn't linked into the right parent/child chain for its event category. The real test is always the live re-run afterward.

## Why it matters

The useful lesson here isn't "Wazuh didn't detect this" — it's that Wazuh partially detected it, badly, and the fix required understanding how its rule engine actually organizes rules into categories, not just writing a rule that matches the right fields. A field-matching rule that looks correct can still silently never run if it isn't hooked into the same evaluation path as the logs it's meant to catch.

## Screenshots

- `schtasks-command.png` — the task creation command succeeding
- `tasksched-log-enabled.png` — enabling the Task Scheduler Operational log in Event Viewer
- `agent-config.png` — the `<localfile>` addition in the agent's `ossec.conf`
- `default-rule-gap.png` — the default rule 67014 firing with its blank description
- `logtest-first-pass.png` — `wazuh-logtest` matching the rule against reconstructed data, before the live fix
- `rule-lookup.png` — the installed ruleset showing rule 67014's real structure, including the `if_sid: 60009` chain
- `correlation-alert.png` — rule 100111 firing correctly live, with the real task name and SYSTEM context in the description

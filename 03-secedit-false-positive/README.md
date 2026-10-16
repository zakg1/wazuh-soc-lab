# The alert that wasn't an attack

## What fired

A level-4 alert on the Windows victim — rule **92066**, "SecEdit.exe binary in a suspicious location launched by PowerShell." `SecEdit.exe` exporting Windows security policy is a real technique sometimes used to check for (or tamper with) local security settings, so on the surface this looked like something worth taking seriously.

## The investigation

Pulled the raw Sysmon event behind the alert and checked the full command line and working directory:

```
commandLine: "C:\Windows\system32\SecEdit.exe" /export /cfg C:\Windows\TEMP\secpol.cfg
currentDirectory: C:\Program Files (x86)\ossec-agent\
```

`currentDirectory` is the giveaway — that's Wazuh's own install path. This wasn't an attacker touching security policy; it was Wazuh's Security Configuration Assessment (SCA) module doing a routine scan of the box's own security settings, something it runs on a schedule as part of normal operation.

## Why this is worth documenting

The rule wasn't wrong to fire — PowerShell spawning SecEdit is a legitimate detection pattern, and a generic ruleset has no way to know in advance that *this specific instance* of it is the monitoring tool checking itself rather than an attacker. Telling the two apart is the actual analyst work: not deleting the rule, and not ignoring the alert, but reading the context and reaching a defensible conclusion.

The tuned Sigma version of this rule — which excludes Wazuh's own agent path so it stops firing on itself without losing the real detection — is written up in the [`Signal & Response`](https://claude.ai/artifact/S3zQsi8BcHAxZYzRnxW4NE) rule-writing course, module 5.

## Screenshots

- `alert-92066.png` — the original alert
- `event-detail-expanded.png` — the expanded Sysmon event showing `currentDirectory`

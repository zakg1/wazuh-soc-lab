# SSH brute-force → correlated detection

## The attack

Ran Hydra from Kali against the Linux victim's SSH port with a small wordlist of common weak passwords, none of which matched the real account.

```bash
hydra -l <username> -P /tmp/passwords.txt ssh://<victim-ip> -t 4
```

## What Wazuh saw

Every failed login came in individually as rule **5760** ("sshd: authentication failed"), severity level 5 — low enough on its own that it'd get lost in normal noise. Once enough of them landed inside a short window, Wazuh's correlation logic escalated to rule **5763** ("sshd: brute force trying to get access to the system"), severity level 10.

Linux's PAM layer caught the same activity independently, from a completely separate log source: rule **5551** ("PAM: Multiple failed logins"), also level 10.

## A note on timing

Rule 5763 only escalates once it sees 8+ rule-5760 failures from the same source IP inside a 120-second window. The first run here didn't clear that bar — Hydra got stopped too early. Letting it run uninterrupted for a couple of minutes was enough to trigger it. Worth checking a correlation rule's actual threshold before assuming it's broken.

## Why it matters

A single failed login is meaningless — it happens on every internet-facing box constantly. The escalation from individual level-5 events into one level-10 alert is what actually makes this SIEM behavior useful: it's counting, grouping by source, and only raising its voice once the pattern is unambiguous.

This is the same shape as the custom Nmap-detection rule in [`../04-nmap-custom-rule`](../04-nmap-custom-rule) — noisy individually, decisive as a group.

## Screenshots

- `hydra-command.png` — the attack as run from Kali
- `alert-stack.png` — the stack of individual 5760 events
- `correlation-alert.png` — rule 5763 and PAM's 5551, expanded

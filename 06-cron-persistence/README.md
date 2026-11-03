# Scenario 06: cron persistence (T1053.003)

## The attack

Added a cron job on the Linux victim to simulate an attacker setting up a scheduled task for persistence — the Linux equivalent of the registry run-key and scheduled-task scenarios already covered on the Windows side.

```bash
( crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/update.sh") | crontab -
```

That installs a job running `/tmp/update.sh` every 5 minutes, written in a way that preserves any existing crontab entries instead of overwriting them — the same technique a real persistence mechanism would use to stay quiet.

First attempt at this failed outright, on a detail worth keeping in the writeup rather than editing out: the string was missing a space between the fifth cron field and the command (`*/5 * * * */tmp/update.sh` instead of `*/5 * * * * /tmp/update.sh`), so cron tried to parse `*/tmp/update.sh` as the day-of-week field and rejected the whole file. Fixing the spacing and rerunning it installed cleanly, confirmed with:

```bash
crontab -l
```

## The detection

Wazuh doesn't need a custom rule for this one — crontab changes are covered out of the box, since `/var/spool/cron/crontabs` and `/etc/cron.d` just needed to be added to the agent's file integrity monitoring scope. On the agent (`/var/ossec/etc/ossec.conf`), inside the `<syscheck>` block:

```xml
<directories realtime="yes" check_all="yes">/var/spool/cron/crontabs,/etc/cron.d</directories>
```

`realtime="yes"` means Wazuh picks up the change immediately rather than waiting for the next scheduled scan, and `check_all="yes"` means it hashes the full file rather than just checking metadata like size or permissions — worth having on a directory this small and this security-relevant.

The corrected cron command produced two alerts at the same timestamp, not one:

- **Rule 2832**, "Crontab entry changed" — a rule Wazuh ships specifically for crontab modifications, not just generic file monitoring.
- **Rule 554**, "File added to the system" — the FIM rule picking up the underlying write to `/var/spool/cron/crontabs`, from the directory addition above.

Getting both is a stronger result than planning for just one. The crontab-specific rule confirms Wazuh actually understands what kind of file changed, not just that *a* file changed, and the generic FIM rule is the fallback that would still catch it even if the dedicated rule didn't exist.

## Verifying it

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Feed it a line from `/var/log/syslog` or journald around the time the crontab command ran, and confirm it decodes as a crontab-related log line before trusting the live alert.

## Why it matters

Persistence through cron is one of the oldest tricks on Linux, and it's quiet by design — a single new line in a file nobody looks at regularly. Having both a purpose-built detection and a general-purpose fallback watching the same spot is the kind of defense-in-depth that matters more than either one alone.

## Screenshots

- `cron-install-fail.png` — the first attempt failing on a cron syntax error
- `cron-command.png` — the corrected command installing successfully
- `cron-verify.png` — `crontab -l` confirming the new entry
- `syscheck-config.png` — the `<syscheck>` directory addition on the agent
- `correlation-alert.png` — rules 2832 and 554 firing together
- `alert-detail.png` — expanded detail on the rule 2832 alert

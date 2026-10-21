# Closing a visibility gap: Nmap wasn't detected

## The problem

Ran a full Nmap scan from Kali against the Linux victim. Nothing showed up in Wazuh — not an error, just silence.

That's not a Wazuh bug. Its agent is host-based: it ships logs that something on the box already wrote. By default, nothing on a stock Ubuntu install writes a log line when a port gets probed, so there was nothing for the agent to forward in the first place.

## The fix

Enabled UFW and turned its logging on:

```bash
sudo ufw enable
sudo ufw logging on
```

A blocked probe now writes a line like:

```
Oct 16 11:06:59 ubuserver kernel: [UFW BLOCK] IN=ens33 OUT= MAC=00:0c:29:e7:da:d7:00:0c:29:5a:9f:a0:08:00
  SRC=192.168.199.129 DST=192.168.199.128 LEN=44 TOS=0x00 PREC=0x00 TTL=56 ID=29765
  PROTO=TCP SPT=57022 DPT=8888 WINDOW=1024 RES=0x00 SYN URGP=0
```

From there it took a custom decoder and two rules to turn that raw line into something the rule engine could act on. [`decoder.xml`](./decoder.xml) pulls `srcip`, `dstip`, `protocol`, `srcport`, and `dstport` out of each line. [`local_rules.xml`](./local_rules.xml) escalates from a quiet per-packet alert to a real "this looks like a scan" alert once the same source trips it 8+ times in 20 seconds, tagged to MITRE T1046 (Network Service Discovery).

## Getting there wasn't the clean version

The first draft of this decoder looked reasonable on paper and failed in four separate ways once it hit a live system.

A regex syntax error, to start. The prematch field used escaped square brackets around `UFW BLOCK`, and Wazuh's regex engine rejected the escaping outright. Dropping the brackets and matching on the bare text fixed it.

Then silence, with no error at all. Wazuh's pre-decoder couldn't parse this system's ISO 8601 journald timestamps, so no `program_name` field ever got extracted for the decoder to key on. The decoder was syntactically fine; it just never had anything to match against.

Once that was sorted, a different decoder matched instead of mine. Wazuh ships a built-in decoder literally named `kernel`, and it claimed the log line first. The fix was making my decoder a child of that built-in one (`<parent>kernel</parent>`) rather than competing for the same program name — which meant collapsing what was originally two decoders into one, since Wazuh only supports one level of parent/child nesting, not a grandchild.

Last one: even with the fields extracting correctly, the rule still wouldn't fire. It checked for `<decoded_as>ufw-block</decoded_as>`, but the decoder that actually won reported itself as `kernel`. Matching on the real decoder name, plus an explicit text match on `UFW BLOCK` so it doesn't fire on every unrelated kernel log line on the box, closed it out.

Every one of those four was caught with `wazuh-logtest` before touching the live manager config, which turned what could have been hours of restart-scan-check into something closer to a checklist.

## Verifying it

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a line from `/var/log/ufw.log` in and confirm Phase 2 shows the extracted fields, and Phase 3 shows rule 100100 (or 100101, if the frequency threshold's already been tripped) firing. Then re-run the actual scan and check the dashboard for the level-10 alert.

## Deploying it

Copy `decoder.xml` into `/var/ossec/etc/decoders/local_decoder.xml` and `local_rules.xml` into `/var/ossec/etc/rules/local_rules.xml` on the manager, then:

```bash
sudo systemctl restart wazuh-manager
```

## Why it matters

This is the same "individually noisy, collectively decisive" pattern behind the SSH brute-force correlation in [`../01-bruteforce-ssh`](../01-bruteforce-ssh) — just written by hand instead of shipped by default. Most of what a detection engineer does day to day isn't running tools that already work out of the box. It's noticing where visibility has a hole, and building the piece that closes it, even when the first attempt at building it doesn't work.

## Screenshots

- `nmap-scan.png` — the Nmap scan running against the victim
- `ufw-log-line.png` — the filtered UFW log showing blocked probes from the attacker's IP
- `decoder-test.png` — `wazuh-logtest` output confirming the decoder parses the line and rule 100100 fires
- `correlation-alert.png` — the dashboard showing individual level-3 alerts next to the single level-10 correlation alert
- `alert-detail.png` — the expanded level-10 alert, showing rule 100101, the frequency threshold, and the MITRE T1046 mapping
- `rule-config.png` — the final rule definitions on the manager

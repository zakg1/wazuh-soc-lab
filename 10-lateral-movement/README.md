# Scenario 10: lateral movement via password reuse (T1021)

**MITRE ATT&CK:** T1021, Remote Services (SSH); T1078, Valid Accounts
**Machines:** Kali (attacker), `maswin` (Windows, compromised in scenario 09), `masubu` (Linux)
**Manager:** Wazuh 4.14.7

## What I did

This scenario simulates what happens after a successful attack, not during one. In scenario 09 I cracked the RDP password for `wigga` on `maswin` with Hydra. Here, I treat that as a real foothold: the attacker reuses the same username and password to reach a second machine, `masubu`, over SSH.

I created a matching `wigga` account on `masubu` with the same password (`01`), then from Kali, pretending to already be on the compromised host, SSH'd into `masubu` with it:

```
ssh wigga@192.168.199.128
```

The first attempt was a typo, the second succeeded (`02`).

## What I expected to find, and what I actually found

I expected a detection gap, the same pattern as scenarios 08 and 09. Instead I found the opposite: Wazuh's stock SSH rules already tag both the failed and successful login with MITRE's Lateral Movement tactic, no custom rule needed for that part. Rule 5760 (failed) carries T1110.001 and T1021.004. Rule 5715 (successful) carries T1078 and T1021.

The real gap was severity, not coverage. Rule 5715 fires at level 3, the same tier as any routine, legitimate login. Nothing about it stands out. And nothing connects it to the fact that this exact source IP had just finished brute-forcing a different machine minutes earlier. A successful lateral-movement login is supposed to look like a normal one, and here it did, even with MITRE tags already attached.

## The fix: a watchlist, not a bigger rule

Rather than try to correlate two separate hosts' events by timing, which Wazuh doesn't do cleanly across agents, I used a CDB list: a simple watchlist of IPs that have already done something suspicious elsewhere in the lab. If a successful login comes from a listed IP, it gets escalated.

```
sudo nano /var/ossec/etc/lists/suspicious_sources
```
```
192.168.199.129:
```

Registered it in `ossec.conf`:
```xml
<list>etc/lists/suspicious_sources</list>
```

Wazuh compiles CDB lists into their binary `.cdb` form automatically on restart in this version — there's no separate build command anymore (`03`).

## Custom rule

Rule **100140**, level 12, in `local_rules.xml` (`04`):

```xml
<group name="local,lateral_movement,">
<rule id="100140" level="12">
<if_sid>5715</if_sid>
<list field="srcip" lookup="match_key">etc/lists/suspicious_sources</list>
<description>Successful login from a source already flagged elsewhere - possible lateral movement: $(srcip)</description>
<mitre>
<id>T1021</id>
</mitre>
<group>lateral_movement,</group>
</rule>
</group>
```

It chains off 5715 (the stock successful-SSH rule) and checks the source IP against the list. A match jumps it from level 3 to level 12 (`05`, `06`).

I got the `lookup` attribute wrong twice before this worked. I first guessed `address_match`, which doesn't exist in this version; the stock rules that match on `srcip` all use `lookup="match_key"`, which I found by grepping the existing ruleset instead of guessing again.

## Limitation

This watchlist only knows about an IP after something else has already flagged it, so it adds nothing on a first-ever move into the lab, only on a second or later one. It's also a flat IP list with no expiry, so a real deployment would need to age entries out or they'd stay flagged forever. And it's a manual list here; a production setup would populate it automatically from earlier alerts instead of me typing the IP in by hand.

## What I took from this

Not every gap is a missing rule. Sometimes detection logic is already correct and still useless in practice, because nothing tells a human or a dashboard to actually look at it. A level-3 alert with the right MITRE tag buried among routine logins might as well not exist. Turning that into something that gets noticed took a completely different technique than the field-matching rules from earlier scenarios: a watchlist that carries context from one event into a judgment about a completely unrelated one.

## Next

Still deciding — possibly data exfiltration detection, or circling back to the agent registration conflict ("Agent key already in use") noted back in scenario 08.

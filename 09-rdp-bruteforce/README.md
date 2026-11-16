# Scenario 09: RDP brute force (T1110)

**MITRE ATT&CK:** T1110, Brute Force
**Victim:** Windows agent `maswin` (RDP enabled, Sysmon + Wazuh agent)
**Manager:** Wazuh 4.14.7
**Attack tool:** Hydra (RDP module) from Kali

## What I did

RDP is off by default on the Windows victim, so I enabled it and opened the firewall rule, then confirmed the port from Kali:

```
nmap -p 3389 192.168.199.130
```

Port 3389 was open (`01`). I ran Hydra against it with a short password list containing a few wrong passwords and the real one, rather than a full wordlist — RDP's handshake is slow, so a brute force against it takes much longer per attempt than SSH does. Hydra found the real password after the wrong ones failed (`02`).

Before attacking, I checked that Windows was actually set up to log this. Audit policy for Logon was already set to log success and failure, and the Wazuh agent forwards the Security event log, so Event 4625 (failed logon) and 4624 (successful logon) both reach the manager.

## What caught it

Wazuh's stock rule **60122** catches each individual failed logon, level 5 (`03`, `04`). It matched correctly: Logon Type 3, NTLM, source IP `192.168.199.129` (Kali), account `wigga`, status `0xC000006D` ("Unknown user name or bad password").

What Wazuh does **not** ship is anything that turns a burst of those into a single brute-force alert. The SSH scenario earlier in this lab has exactly that correlation built in out of the box. Windows logons don't.

## Custom rule

Rule **100130**, level 10, in `local_rules.xml` (`05`):

```xml
<group name="local,windows,brute_force,">
<rule id="100130" level="10" frequency="8" timeframe="120">
<if_matched_sid>60122</if_matched_sid>
<description>Multiple Windows logon failures from the same source - possible brute force: $(win.eventdata.ipAddress)</description>
<mitre>
<id>T1110</id>
</mitre>
<group>authentication_failures,</group>
</rule>
</group>
```

It fires when 8 occurrences of rule 60122 happen within 120 seconds. I matched the 8/120 threshold to the SSH rule already documented earlier in this lab, so both read as one consistent brute-force baseline.

It fired on both Hydra runs I tested (`06`), correctly showing the source IP in the description.

## Limitation

`if_matched_sid` counts matches per agent, not per source IP. A single user mistyping their own password 8 times from one machine would trip this rule too, same as it would've caught the real attack. A tighter version would need to group by source IP specifically, which Wazuh's frequency rules don't do without extra fields I haven't set up yet.

## What I took from this

Wazuh's correlation coverage is inconsistent across platforms. SSH gets a brute-force rule for free; RDP and other Windows logon types don't, even though the raw event and the single-failure rule are both there. Checking for this kind of gap — not just "does the event get logged" but "does anything correlate repeated events into one alert" — is its own step, separate from confirming the base telemetry works.

## Next

Lateral movement detection across both machines at once.

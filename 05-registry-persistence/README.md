# Scenario 05: registry Run key persistence (T1547.001)

## The attack

Wrote a Run key so a program launches automatically at every login, a common post-compromise move because it needs no special privileges when scoped to the current user (HKCU rather than HKLM).

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdaterSvc" /t REG_SZ /d "C:\Users\Public\update.exe"
```

## First attempt: a typo that still got caught

The first run had a typo in the key path: `HKCU\Sofware\Windows\CurrentVersion\Run`, with "Software" misspelled and `Microsoft\` missing entirely. `reg add` doesn't complain about this. It creates any missing subkeys on the way, so the command reported "The operation completed successfully" while quietly building a registry path that Windows never reads at logon. It wasn't persistence at all, just a registry write to a made-up location.

Wazuh flagged it anyway: rule 92041, level 10, "Value added to registry key has Base64-like pattern." That's useful to know. The rule fired at a path that doesn't exist, so it isn't tied to recognizing the real Run key. It keys on something about the value being written. I didn't dig into exactly why `C:\Users\Public\update.exe` looked Base64-like to it.

## Second attempt: the real path

Reran it against the correct key. Two alerts this time:

- Rule 92041, level 10, the same Base64-like pattern alert as before.
- Rule 92302, level 6, "Registry entry to be executed on next logon was modified using command line application reg.exe."

92302 is the one that actually describes the technique, and it only showed up with the real Run key path. The typo'd run never triggered it. So the two rules are doing different jobs: 92302 knows what the Run key is, 92041 is a generic check on what's being written.

One odd detail: the generic rule scored higher (level 10) than the persistence-specific one (level 6). In a real queue that ordering would push the vague alert above the one that names what's happening.

No custom rule or config change was needed for this scenario. Sysmon's registry events are what make the write visible at all; without them Windows' default logging barely touches the registry.

## Why it matters

Registry Run keys are one of the oldest persistence mechanisms and still among the most common. They survive reboots, they need no admin rights in the HKCU case, and the entry is one short string among everything else under that key. The typo run is a decent reminder that a command succeeding doesn't mean it did what you meant, which holds for attackers and for lab notes alike.

## Screenshots

- `reg-add-typo.png`: the first command, with the misspelled path
- `alert-typo-path.png`: rule 92041 firing on the bogus path
- `reg-add-command.png`: the corrected command succeeding
- `wazuh-alert-persistence.png`: rules 92302 and 92041 firing together on the real path
- `alert-detail.png`: the expanded detail panel on the 92302 alert

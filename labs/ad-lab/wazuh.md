# Wazuh SIEM: Build, Agents and Custom Detections

## Summary

I added a real SIEM to the lab. Up to now my detections were manual `Get-WinEvent` hunts. Now Wazuh collects the logs from the whole lab and runs my detection rules on them automatically. I built the server, enrolled agents on the Windows boxes, wrote three custom rules, and then spent most of the night on one of them that quietly refused to fire. The reason it didn't fire turned out to be the best lesson in here.

## The build

Wazuh runs on its own VM, `10.10.10.40`, on the same isolated lab network as the DC, the Windows 11 client and Kali. The network is NAT, so the VM can reach out for packages but nothing from outside can reach in.

I didn't click through the Ubuntu installer. The graphical server installer can't be driven remotely, so I used the Ubuntu 24.04 **cloud image** plus a cloud-init seed instead. That boots a pre-installed system and configures itself on first boot: static IP, my SSH key, hostname, passwordless sudo. The whole VM was up and reachable over SSH in about ten seconds.

Then the Wazuh all-in-one installer (indexer + manager + dashboard on one host):

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i
```

Version 4.14.9. The dashboard comes up on `https://10.10.10.40`.

## The agents

The Wazuh agent ships Windows logs to the manager. It talks to the manager by IP, so it works even when DNS is down (I found that out the hard way: the DC was off for a while, so the Windows 11 client had no DNS and couldn't download anything from the internet. I served the installer to it from the Wazuh box by IP instead).

Install on each Windows host, pointed at the manager:

```powershell
msiexec.exe /i wazuh-agent.msi /qn WAZUH_MANAGER="10.10.10.40" WAZUH_AGENT_NAME="WIN11"
Start-Service WazuhSvc
```

I enrolled the Windows 11 client and the domain controller. Both show as Active on the manager:

```
ID: 001, Name: WIN11, IP: any, Active
ID: 002, Name: DC01,  IP: any, Active
```

The default agent collects the Application, Security and System channels. It does not collect Sysmon, so I added that channel centrally from the manager (shared agent config, no editing files on Windows):

```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

After that, Security events (4688, 4769, logons) and Sysmon events (process, network, DNS) both flow into the SIEM.

## The custom rules

I wrote three rules in `local_rules.xml`, carried over from the attacks I'd already run:

- **100210 Kerberoasting** - a service ticket (4769) requested for a service account. It matches AES (`0x12`) as well as RC4 (`0x17`), because my Server 2025 domain is AES only and an RC4-only rule would miss the roast. It excludes machine accounts and krbtgt.
- **100220 LLMNR/NBT-NS** - a host sending LLMNR (UDP 5355) or NBT-NS (UDP 137) broadcasts, which is Responder poisoning territory.
- **100221 Rogue SMB** - a client authenticating over 445 to a host that isn't the DC.

## The one that wouldn't fire

I ran the Kerberoast again to test rule 100210:

```powershell
klist purge
klist get MSSQLSvc/sql01.purple.internal:1433
```

Nothing alerted. So I went down the chain to find out why.

First I proved the event was actually reaching Wazuh. I turned on full archiving (`logall_json`), which logs every event the manager receives, not just the ones that alert. The 4769 for `svc_sql` was there, decoded perfectly: `serviceName=svc_sql`, `ticketEncryptionType=0x12` (AES256), the lot. So the telemetry was fine and my rule logic was fine. The event simply wasn't producing an alert.

The strange part: the domain controller's own 4769s (for `DC01$` and `krbtgt`) **did** alert, as the built-in "Windows Logon Success" rule. My `svc_sql` 4769 was identical to them in every system field: same decoder, same event ID, same audit-success flag. Even a clean reboot of the whole SIEM didn't change it.

The answer was a **built-in Wazuh rule**, 92651:

```xml
<rule id="92651" level="0">
  <if_sid>60106</if_sid>
  <field name="win.eventdata.ipAddress" type="pcre2">(?:[0-9]{1,3}\.){3}[0-9]{1,3}</field>
  <field name="win.eventdata.ipAddress" type="pcre2" negate="yes">127\.0\.0\.1</field>
  <description>Successful Remote Logon ... (ignored)</description>
</rule>
```

It is a **noise-reduction rule, level 0, that silences any successful remote logon or ticket request coming from a real IP address**. My roast came from the Windows 11 client (`10.10.10.20`), a real IP, so it was swallowed. The DC's own tickets came from loopback (`::1`), so they dodged this filter and alerted. That one difference, the client IP, was the whole mystery.

## The fix

The fix is to anchor my rule as a **child of the silencer**, so it re-raises the event instead of fighting it:

```xml
<rule id="100210" level="10">
  <if_sid>92651</if_sid>
  <field name="win.system.eventID">4769</field>
  <field name="win.eventdata.serviceName" negate="yes" type="pcre2">\$$|^krbtgt$</field>
  <field name="win.eventdata.ticketEncryptionType" type="pcre2">^0x(12|17)$</field>
  <description>Kerberoasting: service ticket (4769) for $(win.eventdata.serviceName), enc $(win.eventdata.ticketEncryptionType)</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

This is also a sharper detection than what I started with. A service ticket requested by a **remote client** is exactly the Kerberoast shape. The DC asking for its own tickets no longer matters.

The alert fires now:

```
RULE 100210  level 10  MITRE T1558.003  (agent: DC01)
svc=svc_sql   enc=0x12 (AES256)   reqUser=Administrator@PURPLE.INTERNAL   srcIP=10.10.10.20
-> Kerberoasting: service ticket (4769) for svc_sql, enc 0x12
```

## What I learned

- A SIEM detection is only as good as what the sensor collects **and** what the ruleset lets through. Built-in noise-reduction rules can silently swallow a real attack. Mine looked perfect on paper and never fired.
- The way to debug that is to turn on full archiving and prove the event reaches the manager, then walk the rule chain to find what's catching it. Guessing at the rule wastes hours.
- To override a built-in "ignore" rule, make your detection a child of it and re-raise the specific case you care about.
- Always test a detection against the live attack, not just the rule logic. If I had only read my own rule, I would have sworn it worked.
- Agents talk to the manager by IP, so they keep working even when name resolution is broken. Handy, and also a reminder that an attacker inside the network doesn't need DNS either.

## Status

Wazuh is collecting Security and Sysmon from both Windows hosts. The Kerberoasting rule fires on the live attack. The LLMNR and rogue-SMB rules are written and loaded, still to be tested against their attacks. Next I'll point the existing attacks at the SIEM and tune each rule against what actually fires.

# Purple Team Journey

Learning both sides of security: how attacks work and how to catch them.

I'm a Bachelor of IT student (Cyber Security major, Application Development minor)
at CQUniversity, building toward a purple team role. This repo tracks everything
I learn, build and break, week by week.

## Roadmap

| Phase | Dates | Focus |
|---|---|---|
| 0. Setup | Oct 2026 | Lab, tools, this repo |
| 1. Roots | Oct - Dec 2026 | Linux, Windows and Active Directory, Python, Bash |
| 2. Blue | Dec 2026 - Feb 2027 | Sysmon, Wazuh, MITRE ATT&CK, detection rules, Azure |
| 3. Red | Feb - Mar 2027 | Recon, web attacks, AD attacks, privilege escalation |
| 4. Purple | Mar 2027 onward | Attack, detect, tune, write up |

Full plan: [ROADMAP.md](ROADMAP.md)

## Repo layout

| Folder | What's in it |
|---|---|
| [weekly-notes](weekly-notes) | What I learned each week |
| [labs](labs) | Lab setup notes and configs |
| [writeups](writeups) | Attack and detection write-ups |
| [scripts](scripts) | Python and Bash tools I've written |
| [templates](templates) | Templates for notes and write-ups |

## Lab

Arch Linux host with KVM (libvirt, virt-manager). VMs: Windows Server 2025 (domain controller), Windows 11, Kali. Build notes in [labs/ad-lab](labs/ad-lab).

## Highlights

| What | Link |
|---|---|
| AD home lab build: DC, domain-joined Windows 11, Kali, and every problem I hit | [labs/ad-lab](labs/ad-lab) |
| Fake company domain: OUs, users, groups, GPOs, Kerberoastable service account | [domain-structure.md](labs/ad-lab/domain-structure.md) |
| Audit logging: one GPO, 10 audit settings, tested with real events (4688, 4771, 4728) | [audit-policy.md](labs/ad-lab/audit-policy.md) |
| Sysmon on Windows 11: one command traced through DNS, network and process events | [sysmon.md](labs/ad-lab/sysmon.md) |
| Kerberoasting attack and detect: AES roast, 4769 shows 0x12 not 0x17, password policy beat the crack | [kerberoasting.md](labs/ad-lab/kerberoasting.md) |
| Latest weekly note | [Week 43](weekly-notes/2026-W43.md) |

![Login banner GPO on Windows 11](labs/ad-lab/screenshots/gpo-login-banner.png)

## Contact

[LinkedIn](https://linkedin.com/in/siddiqueabu)

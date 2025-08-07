# H6thSense

_The hacker-themed, AI-augmented firewall & routing distro (forked from pfSense)_

![logo](src/usr/local/www/img/h6thsense_logo.svg)

---

## Table of Contents

- [What makes it different?](#what-makes-it-different)
- [Directory Quick-Tour](#directory-quick-tour)
- [Building an Image](#building-an-image)
- [First-Boot Quick-Start](#first-boot-quick-start)
- [Periodic Tasks](#periodic-tasks)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ What makes it different?

| Capability              | Description                                                                                           |
|-------------------------|-------------------------------------------------------------------------------------------------------|
| **AI Assistant**        | Chat, voice, or speech-to-text; answers config questions, explains rules, executes changes.           |
| **LLM Provider Plug-ins** | Gemini, Mistral, Groq – selectable per user.                                                        |
| **AI Threat-Monitor**   | Analyzes pf / Snort / Suricata logs, auto-blocks attackers with confidence threshold & TTL.           |
| **MITRE ATT&CK Console**| Every alert auto-mapped to tactic/technique; kill-chain visual and playbook links.                    |
| **Dynamic Deception / Honeypot** | Low-interaction listener with AI-generated banners; scans diverted transparently; hits feed AI confidence. |
| **IDS/IPS Rule Control**| Enable/disable/add rules via chat or one-click in suggestion modal; Emerging-Threats index search.    |
| **Per-Interface & Per-Rule Policies** | Fine-grained enable/disable, custom thresholds & TTL.                                   |
| **Dark “Hacker” UI Theme** | Neon-green, mono-font styling plus custom branding.                                                |

---

## Directory Quick-Tour

- `src/` – Main source code, UI, backend, and widgets
- `build/` – Scripts and configs for image building
- `etc/periodic/daily/` – Periodic tasks for threat feeds and honeypot seeding
- `docs/` – Project documentation and setup guides
- `build/output/` – Build artifacts (ISOs, memstick images, etc.)

---

## Building an Image

```sh
# 1. Install FreeBSD 14 build dependencies (on the host or a bhyve/VM)
pkg install git gmake php81 php81-curl curl bash

# 2. Clone & configure
git clone https://github.com/breakingcircuits1337/pfsense.git
cd pfsense
cp build.conf.sample build.conf   # tweak as needed

# 3. Build appliance ISO / memstick
./build.sh
```

The resulting artifacts land in `build/output/`.
Flash to USB or boot in your favorite hypervisor.

---

## First-Boot Quick-Start

1. Browse to `https://192.168.1.1` → login `admin` / `pfnonsense`.
2. Navigate: Services → AI Assistant Settings
    - Paste API keys for Gemini/Mistral/Groq. ([How to obtain API keys?](#getting-api-keys))
    - Tick **Enable Threat Monitor** and **Enable Honeypot**.
3. Visit Diagnostics → AI Assistant and say “help me secure my WAN”.

---

## Periodic Tasks

Located in `/etc/periodic/daily/`:
- `et_index` – refresh Emerging-Threats index
- `honeypot_seed` – feed scanners into pf honeypot table

Disable by removing the symlinks if not required.

---

## Contributing

PRs welcome – follow [PSR-2 coding style](https://www.php-fig.org/psr/psr-2/) (see `.editorconfig`).
- New ATT&CK mappings: edit `attack.inc`.
- Custom UI widgets: place PHP under `src/usr/local/www/widgets/`.

Star ⭐ the repo and spread the (non)sense!

---

## License

[Insert your license here, e.g., MIT, GPL, etc. If you have a LICENSE file, reference or link it.]
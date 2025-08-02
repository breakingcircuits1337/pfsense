# BC's PFnonSense

## # BC’s PFnonsense
_The hacker-themed, AI-augmented firewall & routing distro (forked from pfSense)_

![logo](src/usr/local/www/img/bc_logo.svg)

---

## ✨ What makes it different?

| Capability | Description |
|------------|-------------|
| **AI Assistant** | Chat, voice or speech-to-text; answers config questions, explains rules, executes changes. |
| **LLM Provider Plug-ins** | Gemini, Mistral, Groq – selectable per user. |
| **AI Threat-Monitor** | Analyses pf / Snort / Suricata logs, auto-blocks attackers with confidence threshold & TTL. |
| **MITRE ATT&CK Console** | Every alert auto-mapped to tactic/technique; kill-chain visual and playbook links. |
| **Dynamic Deception / Honeypot** | Low-interaction listener with AI-generated banners; scans diverted transparently; hits feed AI confidence. |
| **IDS/IPS Rule Control** | Enable/disable/add rules via chat or one-click in suggestion modal; Emerging-Threats index search. |
| **Per-Interface & Per-Rule Policies** | Fine-grained enable/disable, custom thresholds & TTL. |
| **Dark “Hacker” UI Theme** | Neon-green, mono-font styling plus custom branding. |

---

## Directory quick-tour

---

## Building an image

```sh
# 1. Install FreeBSD 14 build deps (on the host or a bhyve/VM)
pkg install git gmake php81 php81-curl curl bash

# 2. Clone & configure
git clone https://github.com/your-org/PFnonsense.git
cd PFnonsense
cp build.conf.sample build.conf   # tweak as needed

# 3. Build appliance ISO / memstick
./build.sh

The resulting artefacts land in build/output/
Flash to USB or boot in your favourite hypervisor.
First-boot quick-start

    Browse to https://192.168.1.1 → login admin / pfnonsense.
    Navigate: Services → AI Assistant Settings
        Paste API keys for Gemini/Mistral/Groq.
        Tick Enable Threat Monitor and Enable Honeypot.
    Visit Diagnostics → AI Assistant and say “help me secure my WAN”.


/etc/periodic/daily/
 ├─ et_index      – refresh Emerging-Threats index
 └─ honeypot_seed – feed scanners into pf honeypot table

Disable by removing the symlinks if not required.
Contributing

    PRs welcome – follow PSR-2 coding style (see .editorconfig).
    New ATT&CK mappings: edit attack.inc.
    Custom UI widgets: place PHP under src/usr/local/www/widgets/.

Star ⭐ the repo and spread the (non)sense!

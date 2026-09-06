# VolatileGUI — Volatility 2 & 3 memory analysis platform
![Alt text](./VolatileGUILogoWordmark.svg)

## 🤝 Contributions & Disclaimers

> [!WARNING]
> *    **Work in Progress (WIP):** This is an experimental project and is actively being updated. Breaking changes may occur, and you should test the code thoroughly before using it in any critical applications.
>  *   Additionally, this codebase was built with AI assistance, which means you might encounter unintended behavior or inaccuracies.
> I am actively looking to improve this repository, and your feedback is invaluable. You can help by:
> *   **Reporting bugs:** If you find a mistake, please open an Issue with a brief description of the problem.
> *   **Suggesting improvements:** Feel free to submit a Pull Request with fixes or optimizations.



---

A self-hosted web platform that runs **both** Volatility engines against memory
images, streams the output live into the browser, stores every run in a
searchable history, applies an IOC triage ruleset, and exports analyst reports.

Volatility 2 needs Python 2.7 and Volatility 3 needs Python 3 — they cannot share
an environment. This project solves that by running each engine in its own
container behind an identical tiny HTTP API, so the web app talks to both through
one client and you never touch a Python 2 install.

```
                       ┌──────────────────────────┐
   browser  ◀────SSE────▶│  web  (FastAPI + Jinja) │──── SQLite ── data/
                       └───────────┬──────────────┘
                        NDJSON stream over HTTP
                    ┌──────────────┴───────────────┐
        ┌───────────▼──────────┐      ┌────────────▼─────────┐
        │ vol3  (python 3.11)  │      │ vol2  (python 2.7)   │
        │ volatility3 + shim   │      │ volatility 2.6.1     │
        └───────────┬──────────┘      └────────────┬─────────┘
                    └────────── /evidence ─────────┘  (shared bind mount)
```

---

## Quick start

Works the same way on **Windows** (Docker Desktop) and **Ubuntu/Linux**
(Docker Engine) — everything runs inside containers, so the host OS only
needs Docker itself. Run these from the project folder:

**Linux / macOS / WSL (bash):**

```bash
cp .env.example .env          # optional: change port / worker count
docker compose up -d --build  # first build takes a while (vol2 compiles distorm3)
```

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env   # optional: change port / worker count
docker compose up -d --build  # first build takes a while (vol2 compiles distorm3)
```

Then open **http://localhost:8000** in your browser.

Then either:

* **Upload** an image in the UI (streamed straight to disk — multi-GB is fine), or
* drop files into `./evidence/` on the host and press **Scan evidence folder**.

> Skipping the `cp`/`Copy-Item` step is fine — Compose falls back to the
> defaults baked into `docker-compose.yml` if `.env` doesn't exist.

Check the dashboard: both engine cards should read **online**. If `vol2` is red,
`docker compose logs vol2` will say why (usually still building).

---

## What it does

### Both engines, your choice
Pick Volatility 3 or Volatility 2 per analysis. The plugin picker rebuilds itself
for the chosen engine and the detected OS. Volatility 2 gets a profile selector
pre-filled from `imageinfo`; Volatility 3 resolves symbols itself.

### Popular plugins, presets, or full analysis
* **★ Popular** — one click selects the high-signal plugins (`pslist`, `pstree`,
  `cmdline`, `netscan`, `malfind`, `psxview`, …).
* **Presets** — Quick Triage, Process Deep Dive, Network Activity, Malware Hunt,
  Persistence & Execution, Credentials, Timeline & History, Files & Artefacts.
* **Full Analysis** — every non-destructive plugin for the detected OS.
* **Custom** — search 250+ catalogued plugins by name or description, tick what
  you want, and fill in per-plugin arguments (`--pid`, `--key`, `--dump`, YARA
  rules, …) inline.

### Live execution
Runs are queued and executed by a worker pool. Each run has its own page with a
live console (Server-Sent Events), a progress bar driven by Volatility's own
progress output, and a cancel button that actually kills the process inside the
runner container.

### Results you can work with
Plugin output from both engines is normalised into one table shape, so every
result gets sortable columns, full-text row filtering, pagination, tree
indentation for `pstree`, syntax highlighting for paths/IPs/URLs, and CSV/JSON
export. Volatility 2 plugins with no JSON renderer fall back to text output,
which is then parsed back into a table from its column rule.

### Automatic IOC triage
After every successful run the rules engine looks for, among others:

| Category | Examples |
|---|---|
| Masquerading | `svch0st.exe`, `lsass .exe`, one-character system-process typosquats |
| Process ancestry | `svchost.exe` not parented by `services.exe`, duplicate `lsass.exe`, System not PID 4, orphaned parents |
| Process hiding | present in `psscan` but not `pslist`, `psxview` cross-view gaps |
| Code injection | `malfind` RWX regions, MZ headers in unbacked memory, unbacked thread start addresses |
| Command line | encoded PowerShell, download cradles, Squiblydoo, `certutil -urlcache`, `vssadmin delete shadows`, `net localgroup administrators /add`, Defender tampering |
| Module hiding | `ldrmodules` PEB unlinking, DLLs loaded from `%TEMP%`/`%APPDATA%` |
| Rootkits | SSDT/IDT hooks, callbacks with no owning module, hidden kernel modules, `check_syscall`, `ld.so.preload` |
| Network | connections to 4444/1337/50050/Tor ports, listeners owned by `notepad.exe`, LSASS egress |
| Persistence | service binaries in user-writable paths, services launching script hosts, Run-key LOLBins |
| Credentials | any recovered hash/LSA material flagged for rotation |

Each finding carries a severity, the rule ID, the exact row that triggered it,
and a recommended next step. Findings can be **confirmed** or **dismissed**, and
dismissed ones stop counting toward the risk score. Triage can be re-run over
already-collected results after a rule change — no need to re-run Volatility.

### History, comparison and cases
Every run is kept forever with its command line, exit code, duration, row count
and full log. Filter the history by engine, status, plugin or evidence. The
**Compare** view diffs any two runs — the same plugin before/after an event, the
same plugin on two hosts, or *the same artefact seen by both engines* — and shows
rows present on only one side. Evidence can be grouped into **cases** with rolled
up risk scores.

### Reporting
Generate per-image reports as **HTML**, **PDF** (WeasyPrint), **JSON** (every
row, machine readable) or a **ZIP bundle** (report + per-plugin CSVs + raw logs +
a chain-of-custody README). Reports include hashes, the risk summary, every
finding, and the exact commands that produced each table.

### Also included
* REST API with OpenAPI docs at `/api/docs` — everything the UI does is scriptable.
* SHA-256/MD5 hashing of every image, computed in the background.
* Automatic OS identification and Volatility 2 profile suggestion on import.
* Audit log of every action.
* Plugin catalog browser with plain-English descriptions for both engines.
* Artefact downloads for plugins run with `--dump`.

---

## Layout

```
volatility_project/
├── docker-compose.yml
├── .env.example
├── evidence/            memory images (shared with both runners)
├── symbols/             Volatility 3 ISF symbol tables (Linux/Mac)
├── profiles/            extra Volatility 2 profiles & community plugins
├── data/                SQLite DB, results, logs, generated reports
├── runners/
│   ├── vol3/            python 3.11 + volatility3 + HTTP shim
│   └── vol2/            ubuntu 20.04 + python 2.7 + volatility 2.6.1 + shim
└── web/
    └── app/
        ├── main.py          FastAPI app + lifespan
        ├── config.py        env-driven configuration
        ├── models.py db.py  SQLAlchemy models / session
        ├── catalog.py       curated plugin catalog + presets
        ├── runner_client.py HTTP client for both runners
        ├── worker.py        job queue, execution, persistence
        ├── parsers.py       vol2/vol3 output normalisation
        ├── triage.py        IOC rules engine
        ├── reporting.py     HTML/PDF/JSON/CSV/ZIP export + run diffing
        ├── events.py        SSE pub/sub broker
        ├── routers/         ui.py (pages) + api.py (JSON, streams, uploads)
        ├── templates/       Jinja templates
        └── static/          CSS + vanilla JS (no CDN, works offline)
```

---

## Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `MF_PORT` | 8000 | Published web port |
| `MF_WORKERS` | 2 | Concurrent Volatility jobs |
| `MF_MAX_UPLOAD_GB` | 64 | Upload ceiling |
| `MF_JOB_TIMEOUT` | 7200 | Per-plugin timeout in seconds |
| `MF_SECRET` | — | Change it |
| `TZ` | UTC | Timestamp timezone |

Everything else (default engine, auto-triage, auto-identify, organisation name,
report defaults) is editable in **Settings** at runtime.

---

## Notes on the engines

**Volatility 3 symbols.** Windows symbols are downloaded from Microsoft's symbol
server on first use and cached in the `vol3_cache` volume. Linux and macOS images
need an ISF file — build one with
[`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json) and drop it in
`./symbols/`. Without it, `banners.Banners` will still tell you which kernel you
need.

**Volatility 2 profiles.** Windows profiles ship with Volatility 2. Linux and Mac
profiles are per-kernel zip files — put them in `./profiles/` and they are passed
through as `--plugins=/profiles`. The same folder is where community plugins
(`hollowfind`, `malprocfind`, …) go.

**Which engine for which image?** Volatility 3 is the better default: broader
modern-Windows coverage, no profile hunting, and it handles Windows 10/11 builds
Volatility 2 never learned. Recent releases have also closed much of the old
feature gap — `psxview`, `cmdscan`, `consoles`, `shimcachemem` and a family of
new detectors (`hollowprocesses`, `processghosting`, `unhooked_system_calls`,
`etwpatch`) now exist there. Reach for Volatility 2 for XP/Vista/7 images, for
plugins still unported (`apihooks`, `iehistory`, `evtlogs`, `shellbags`,
`clipboard`, `screenshot`), and as a second opinion — running both and diffing
them in the Compare view is a legitimate anti-rootkit technique in itself.

Some Volatility 3 plugins only appear once their optional dependencies are
present: `hashdump`/`lsadump`/`cachedump` need `pycryptodome`, and the YARA
plugins need `yara-python`. The Docker images install both. Anything missing
shows in the picker as *not installed* rather than failing at run time.

---

## Test images

No memory image handy? Public samples that work well:

* **Volatility Foundation sample images** — <https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>
  (a broad set of Windows/Linux images, many with known malware)
* **MemLabs** (CTF-style Windows images with a walkthrough) —
  <https://github.com/stuxnet999/MemLabs>
* **Ali Hadi's DFIR challenges** — Windows images with documented answers

Download one, drop it into `./evidence/`, press **Scan evidence folder**, then run
**Quick Triage**. `scripts/fetch_sample.sh` prints the current links and will
fetch one for you if you pass a URL (Linux/macOS/WSL/Git Bash — see the
platform notes below for the Windows equivalent).

---

## Running on Windows vs. Ubuntu

Everything the platform does happens inside the three containers, which are
Linux images no matter what the host is — so **Docker is the only thing that
has to work correctly on the host**. There is no other supported way to run
this project (no local/bare-metal Python install path); if `docker compose`
runs, the app runs identically on either OS.

**Ubuntu**
* Install Docker Engine + the Compose plugin (`sudo apt install docker.io
  docker-compose-v2`, or Docker's own apt repo for a newer version), start
  the daemon (`sudo systemctl enable --now docker`), and add yourself to the
  `docker` group (`sudo usermod -aG docker $USER`, then log out/in) so you
  don't need `sudo` for every command.
* Everything in this README's bash examples works as-is.

**Windows**
* Install **Docker Desktop** with the **WSL2 backend** (the default on a
  current install) — that's what makes `docker compose` work from either
  PowerShell or a WSL terminal.
* Run the commands from **PowerShell**, a **WSL** shell, or **Git Bash** —
  not the legacy `cmd.exe`, which doesn't understand `cp` and some of the
  quoting Compose uses. PowerShell examples are given above; inside WSL the
  Linux/bash examples work unchanged.
* Keep the project folder somewhere Docker Desktop shares by default — under
  your Windows user profile (e.g. `C:\Users\you\...`) or, for best I/O
  performance, inside the WSL filesystem itself (`\\wsl$\...` /
  `~/volatility_project` from a WSL shell). If Docker Desktop ever reports it
  can't mount a bind path, check **Settings → Resources → File sharing**.
  First run also triggers a Windows Firewall prompt for `com.docker.backend`
  — allow it, or the containers can't reach each other.
* `scripts/fetch_sample.sh` and `scripts/make.mk` are optional bash/`make`
  conveniences. They run fine from Git Bash or WSL; from plain PowerShell,
  skip them and use the `docker compose ...` commands they wrap directly
  (each one's source is short and readable). Neither is required to build,
  run, or use the platform — only `docker compose up -d --build` is.
* Large memory images: give Docker Desktop enough RAM/disk in **Settings →
  Resources** (the WSL2 VM has its own memory ceiling, separate from
  Windows's). On native Ubuntu, Docker uses the host's resources directly, so
  this step doesn't apply there.
* A `.gitattributes` in this repo pins LF line endings for the shell scripts,
  Dockerfiles, and Makefile, so cloning with Windows's default
  `core.autocrlf=true` doesn't corrupt them.

---

## Security

This platform executes forensic tooling against untrusted memory images and has
**no authentication** — it is built to run on your analysis workstation, bound to
`localhost`. Do not expose port 8000 to a network you do not control. If you need
multi-user access, put it behind an authenticating reverse proxy.

The runner containers are the isolation boundary: the web app never executes
Volatility itself, and each engine only ever sees the evidence mount.

## Licence

Volatility 2 and Volatility 3 are © the Volatility Foundation and licensed under
GPLv2 / the Volatility Software License respectively. This platform orchestrates
them; it does not vendor or modify their code.

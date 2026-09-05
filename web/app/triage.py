"""
IOC / auto-triage rules engine.

Runs over the *normalised* output of a plugin (see parsers.py) and emits
findings.  Rules may also look at previously-collected results for the same
evidence item (the `context` dict, keyed by plugin family), which is how
cross-view checks like "in psscan but not in pslist" work.

Every rule is deliberately conservative about wording: these are indicators,
not verdicts, and each finding carries the row that triggered it so an analyst
can confirm or dismiss it.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Dict, List

from .parsers import as_int, as_text, field, to_dicts

SEVERITY_SCORE = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 1}

# ---------------------------------------------------------------------------
# reference data
# ---------------------------------------------------------------------------
SYSTEM_PROCS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "lsm.exe", "explorer.exe",
    "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "dwm.exe", "conhost.exe",
    "runtimebroker.exe", "sihost.exe", "fontdrvhost.exe", "searchindexer.exe",
    "memory compression", "registry", "userinit.exe", "ctfmon.exe",
}

EXPECTED_PARENT = {
    "smss.exe": {"system"},
    "csrss.exe": {"smss.exe", ""},
    "wininit.exe": {"smss.exe", ""},
    "winlogon.exe": {"smss.exe", ""},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "taskhost.exe": {"svchost.exe"},
    "explorer.exe": {"userinit.exe", "winlogon.exe", ""},
    "runtimebroker.exe": {"svchost.exe"},
    "searchindexer.exe": {"services.exe"},
    "sihost.exe": {"svchost.exe"},
    "dwm.exe": {"winlogon.exe", "wininit.exe", "svchost.exe"},
    "wininet.exe": set(),
}

SINGLETON_PROCS = {"lsass.exe", "services.exe", "wininit.exe", "lsm.exe",
                   "winlogon.exe"}

SYSTEM32_PROCS = {
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "spoolsv.exe", "lsm.exe", "taskhostw.exe",
    "conhost.exe", "dwm.exe",
}

OFFENSIVE_TOOLS = {
    "mimikatz": "credential dumping",
    "procdump": "process memory dumping (often used against LSASS)",
    "psexec": "remote execution",
    "paexec": "remote execution (PsExec clone)",
    "psexesvc": "PsExec service payload",
    "nc.exe": "netcat",
    "ncat": "netcat",
    "plink": "SSH tunnelling",
    "rclone": "bulk data exfiltration",
    "adfind": "Active Directory reconnaissance",
    "lazagne": "credential harvesting",
    "sharphound": "AD attack-path collection",
    "bloodhound": "AD attack-path analysis",
    "winpeas": "privilege escalation enumeration",
    "seatbelt": "host enumeration",
    "rubeus": "Kerberos abuse",
    "cobaltstrike": "C2 framework",
    "beacon.exe": "Cobalt Strike beacon",
    "meterpreter": "Metasploit payload",
    "mimilib": "Mimikatz support library",
    "wce.exe": "Windows Credential Editor",
    "pwdump": "credential dumping",
    "gsecdump": "credential dumping",
    "anydesk": "remote access tool",
    "teamviewer": "remote access tool",
    "ngrok": "tunnelling / egress",
    "advanced_port_scanner": "network scanning",
    "advanced_ip_scanner": "network scanning",
    "netscan.exe": "network scanning",
}

SUSPICIOUS_DIRS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp", r"\\appdata\\roaming",
    r"\\programdata\\", r"\\users\\public\\", r"\\windows\\tasks\\",
    r"\\perflogs\\", r"\\recycler", r"\\\$recycle\.bin", r"\\windows\\debug\\",
    r"\\windows\\fonts\\", r"\\windows\\addins\\", r"\\intel\\logs",
    r"^/tmp/", r"^/dev/shm/", r"^/var/tmp/", r"/\.\w+/",
]
SUSPICIOUS_DIR_RE = re.compile("|".join(SUSPICIOUS_DIRS), re.I)

LOLBIN_PATTERNS = [
    (r"powershell(\.exe)?[^\n]*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
     "critical", "Base64-encoded PowerShell command line"),
    (r"frombase64string", "high", "PowerShell decoding a Base64 payload in memory"),
    (r"(iex|invoke-expression)\s*\(", "high", "PowerShell Invoke-Expression of dynamic content"),
    (r"(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|wget|curl)\s",
     "high", "In-memory download cradle"),
    (r"-nop\b|-noprofile\b", "medium", "PowerShell launched with -NoProfile"),
    (r"-w(indowstyle)?\s+hidden|-windowstyle\s+h", "high", "Hidden PowerShell window"),
    (r"-ep\s+bypass|-executionpolicy\s+bypass", "high", "PowerShell execution policy bypass"),
    (r"regsvr32[^\n]*scrobj\.dll", "critical", "Squiblydoo (regsvr32 + scrobj.dll) execution"),
    (r"rundll32[^\n]*javascript:", "critical", "rundll32 executing JavaScript"),
    (r"mshta[^\n]*(http|javascript:|vbscript:)", "critical", "mshta executing remote/inline script"),
    (r"certutil[^\n]*(-urlcache|-decode|-encode)", "high",
     "certutil used to download or decode a payload"),
    (r"bitsadmin[^\n]*/transfer", "high", "bitsadmin used to transfer a file"),
    (r"wmic[^\n]*process\s+call\s+create", "high", "WMI process creation"),
    (r"vssadmin[^\n]*delete\s+shadows", "critical", "Shadow copy deletion (ransomware behaviour)"),
    (r"wbadmin[^\n]*delete", "critical", "Backup deletion (ransomware behaviour)"),
    (r"bcdedit[^\n]*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)",
     "critical", "Boot recovery disabled (ransomware behaviour)"),
    (r"cipher[^\n]*/w", "high", "Free-space wiping"),
    (r"schtasks[^\n]*/create", "medium", "Scheduled task created"),
    (r"reg(\.exe)?\s+add[^\n]*(currentversion\\\\run|currentversion\\run)", "high",
     "Registry Run key persistence"),
    (r"net(\.exe)?\s+user[^\n]*/add", "high", "Local account created"),
    (r"net(\.exe)?\s+localgroup[^\n]*administrators[^\n]*/add", "critical",
     "Account added to local Administrators"),
    (r"add-mppreference[^\n]*exclusionpath|set-mppreference[^\n]*disable", "critical",
     "Windows Defender tampering"),
    (r"nltest[^\n]*/domain_trusts|whoami\s+/all|net\s+group[^\n]*domain\s+admins",
     "medium", "Domain reconnaissance command"),
    (r"\bcurl\b[^\n]*\|\s*(sh|bash)|\bwget\b[^\n]*\|\s*(sh|bash)", "critical",
     "Remote script piped straight into a shell"),
    (r"\bnc\b[^\n]*\s-[a-z]*e\s", "critical", "Netcat with command execution (-e)"),
    (r"base64\s+-d|openssl\s+enc\s+-d", "medium", "Base64/OpenSSL decoding in a shell"),
    (r"history\s+-c|>\s*~/\.bash_history", "high", "Shell history cleared"),
    (r"chattr\s+\+i|\bchmod\s+[0-7]*777\b", "medium", "Suspicious permission/attribute change"),
    (r"/etc/ld\.so\.preload", "critical", "ld.so.preload manipulation (userland rootkit)"),
    (r"insmod\s|modprobe\s", "medium", "Kernel module loaded from a shell"),
]

SUSPICIOUS_PORTS = {
    4444: "Metasploit default", 4445: "Metasploit default",
    1337: "common backdoor", 31337: "Back Orifice / elite",
    5555: "common RAT", 6666: "common IRC bot / RAT",
    6667: "IRC (botnet C2)", 6697: "IRC over TLS",
    9001: "Tor ORPort", 9050: "Tor SOCKS", 9051: "Tor control",
    1080: "SOCKS proxy", 8081: "alternate HTTP C2",
    50050: "Cobalt Strike team server",
}

NO_NETWORK_PROCS = {
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe", "write.exe",
    "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe", "conhost.exe",
    "cmd.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe",
    "hh.exe", "print.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "acrord32.exe",
}
# Office/PDF apps do legitimately use the network, but a *listening socket*
# owned by one is not normal — handled separately below.

RWX = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "RWX", "6", "0x40"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _finding(rule_id, severity, category, title, detail, row=None,
             recommendation="") -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "category": category,
        "title": title[:300],
        "detail": detail,
        "recommendation": recommendation,
        "score": SEVERITY_SCORE.get(severity, 1),
        "context": row or {},
    }


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except Exception:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or ip.is_link_local)


def _pname(row: Dict[str, Any]) -> str:
    return as_text(field(row, "name")).strip()


def _truthy_false(value: Any) -> bool:
    """vol2/vol3 render booleans in several ways; detect an explicit 'no'."""
    text = as_text(value).strip().lower()
    return text in ("false", "0", "no", "-", "none")


# ---------------------------------------------------------------------------
# rules, keyed by plugin family
# ---------------------------------------------------------------------------
def rule_processes(rows, ctx) -> List[dict]:
    out: List[dict] = []
    by_pid: Dict[int, Dict[str, Any]] = {}
    counts: Dict[str, int] = {}

    for row in rows:
        pid = as_int(field(row, "pid"))
        if pid >= 0:
            by_pid[pid] = row
        name = _pname(row).lower()
        if name:
            counts[name] = counts.get(name, 0) + 1

    for row in rows:
        name = _pname(row)
        lname = name.lower()
        pid = as_int(field(row, "pid"))
        ppid = as_int(field(row, "ppid"))

        # --- masquerading -------------------------------------------------
        if lname and lname not in SYSTEM_PROCS:
            for sysproc in SYSTEM_PROCS:
                if sysproc in ("system", "registry", "memory compression"):
                    continue
                d = _lev(lname, sysproc)
                if 0 < d <= 1 and len(lname) > 5:
                    out.append(_finding(
                        "proc.masquerade", "critical", "Masquerading",
                        f"Process '{name}' (PID {pid}) closely imitates the system "
                        f"process '{sysproc}'",
                        "A one-character difference from a core Windows process name "
                        "is a classic masquerading technique (T1036.005).",
                        row, "Dump the process image and compare it against the "
                             "legitimate binary; check its parent and command line."))
                    break

        # --- unexpected parent --------------------------------------------
        expected = EXPECTED_PARENT.get(lname)
        if expected is not None and ppid >= 0:
            parent_row = by_pid.get(ppid)
            parent_name = _pname(parent_row).lower() if parent_row else ""
            if parent_name and parent_name not in expected:
                out.append(_finding(
                    "proc.bad_parent", "high", "Process Ancestry",
                    f"{name} (PID {pid}) has an unexpected parent: {parent_name} "
                    f"(PID {ppid})",
                    f"Expected parent(s): {', '.join(sorted(x for x in expected if x)) or 'none'}. "
                    "Unexpected ancestry often indicates process injection, hollowing "
                    "or a masquerading binary.",
                    row, "Review the parent's command line and loaded modules."))

        # --- singleton violations ------------------------------------------
        if lname in SINGLETON_PROCS and counts.get(lname, 0) > 1:
            out.append(_finding(
                "proc.duplicate_singleton", "high", "Process Ancestry",
                f"{counts[lname]} instances of {name} are present",
                f"{name} normally exists exactly once on a running Windows system.",
                row, "Compare the images, parents and start times of each instance."))

        # --- System PID sanity ---------------------------------------------
        if lname == "system" and pid not in (4, -1):
            out.append(_finding(
                "proc.system_pid", "high", "Process Ancestry",
                f"The System process has PID {pid} instead of 4",
                "On Windows the System process is always PID 4.", row))

        # --- offensive tooling ---------------------------------------------
        for tool, purpose in OFFENSIVE_TOOLS.items():
            if tool in lname:
                out.append(_finding(
                    "proc.offensive_tool", "high", "Tooling",
                    f"Known offensive tool running: {name} (PID {pid})",
                    f"'{tool}' is commonly used for {purpose}.", row,
                    "Confirm whether this was authorised administrative activity."))
                break

        # --- zero threads ----------------------------------------------------
        threads = as_int(field(row, "threads"), -1)
        exit_time = as_text(field(row, "exittime")).strip()
        if threads == 0 and not exit_time and lname not in ("registry",):
            out.append(_finding(
                "proc.zero_threads", "medium", "Process Ancestry",
                f"{name} (PID {pid}) has zero threads but no exit time",
                "A live process with no threads is usually a terminated process "
                "still in memory, or an artefact of process hiding.", row))

    # --- orphan processes --------------------------------------------------
    pids = set(by_pid)
    for row in rows:
        ppid = as_int(field(row, "ppid"))
        pid = as_int(field(row, "pid"))
        name = _pname(row)
        if ppid > 4 and ppid not in pids and name.lower() not in ("system", ""):
            out.append(_finding(
                "proc.orphan", "low", "Process Ancestry",
                f"{name} (PID {pid}) references a parent (PID {ppid}) that is not "
                "in the process list",
                "Usually just means the parent exited, but it is also what process "
                "hollowing and parent-PID spoofing look like.", row))
    return out


def rule_cmdline(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        name = _pname(row)
        pid = as_int(field(row, "pid"))
        cmd = as_text(field(row, "cmdline"))
        if not cmd:
            continue
        low = cmd.lower()

        for pattern, severity, title in LOLBIN_PATTERNS:
            if re.search(pattern, low, re.I):
                out.append(_finding(
                    "cmd." + re.sub(r"\W+", "_", title.lower())[:40],
                    severity, "Command Line",
                    f"{title} — {name} (PID {pid})",
                    f"Command line:\n{cmd[:2000]}", row,
                    "Decode the payload and correlate with network and file activity."))

        if SUSPICIOUS_DIR_RE.search(cmd):
            out.append(_finding(
                "cmd.suspicious_path", "medium", "Command Line",
                f"{name} (PID {pid}) executes from or references a user-writable "
                "staging directory",
                f"Command line:\n{cmd[:2000]}", row,
                "User-writable directories (Temp, AppData, ProgramData, /tmp) are "
                "the usual staging ground for dropped payloads."))

        if re.search(r"https?://(\d{1,3}\.){3}\d{1,3}", low):
            out.append(_finding(
                "cmd.raw_ip_url", "high", "Command Line",
                f"{name} (PID {pid}) contains a URL with a raw IP address",
                f"Command line:\n{cmd[:2000]}", row,
                "Raw-IP URLs bypass DNS logging and are common in droppers."))
    return out


def rule_process_scan(rows, ctx) -> List[dict]:
    """psscan vs pslist cross-view: unlinked processes."""
    out: List[dict] = []
    listed = ctx.get("processes") or []
    if not listed:
        return out
    live_pids = {as_int(field(r, "pid")) for r in listed}
    for row in rows:
        pid = as_int(field(row, "pid"))
        name = _pname(row)
        exit_time = as_text(field(row, "exittime")).strip()
        if pid < 0 or pid in live_pids:
            continue
        if exit_time and exit_time not in ("N/A", "-"):
            continue          # simply a terminated process still in the pool
        out.append(_finding(
            "proc.unlinked", "critical", "Process Hiding",
            f"{name or 'unknown'} (PID {pid}) was found by pool scanning but is "
            "absent from the process list",
            "A process visible to psscan but not pslist has been unlinked from "
            "the active process list — direct kernel object manipulation (DKOM).",
            row, "Dump the process and inspect the driver responsible for the "
                 "unlinking."))
    return out


def rule_psxview(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        falses = [k for k, v in row.items()
                  if k.lower() not in ("offset(p)", "name", "pid", "exittime",
                                       "exit time", "pslist", "description")
                  and _truthy_false(v)]
        # pslist itself being False is the strongest signal
        pslist_false = any(k.lower() == "pslist" and _truthy_false(v)
                           for k, v in row.items())
        exit_time = as_text(field(row, "exittime")).strip()
        if exit_time and exit_time not in ("", "-"):
            continue
        if pslist_false:
            out.append(_finding(
                "psxview.hidden", "critical", "Process Hiding",
                f"{_pname(row)} (PID {as_int(field(row,'pid'))}) is missing from "
                "the active process list",
                "psxview compares seven independent enumeration sources; a process "
                "missing from pslist but present elsewhere has been hidden.", row))
        elif len(falses) >= 3:
            out.append(_finding(
                "psxview.partial", "high", "Process Hiding",
                f"{_pname(row)} is invisible to {len(falses)} enumeration methods",
                "Missing from: " + ", ".join(falses), row))
    return out


def rule_malfind(rows, ctx) -> List[dict]:
    out: List[dict] = []
    per_proc: Dict[str, int] = {}
    for row in rows:
        name = _pname(row) or as_text(field(row, "process"))
        pid = as_int(field(row, "pid"))
        key = f"{name}:{pid}"
        per_proc[key] = per_proc.get(key, 0) + 1
        prot = as_text(field(row, "protection")).upper()
        blob = " ".join(as_text(v) for v in row.values())
        has_mz = "4d 5a" in blob.lower() or "MZ" in blob[:400]
        severity = "high"
        why = "Private, executable memory with no file backing."
        if any(p in prot for p in ("EXECUTE_READWRITE", "RWX")):
            severity = "critical"
            why = "Region is PAGE_EXECUTE_READWRITE — writable *and* executable."
        if has_mz:
            severity = "critical"
            why += " A PE header (MZ) is present at the start of the region, so a "\
                   "full executable has been mapped in manually."
        out.append(_finding(
            "malfind.injection", severity, "Code Injection",
            f"Injected/unbacked executable memory in {name} (PID {pid})",
            why, row,
            "Dump the region (--dump) and scan it; correlate with ldrmodules and "
            "suspicious threads for the same PID."))

    for key, count in per_proc.items():
        if count >= 5:
            name, _, pid = key.partition(":")
            out.append(_finding(
                "malfind.many", "high", "Code Injection",
                f"{count} injected regions in {name} (PID {pid})",
                "A high number of unbacked executable regions in one process is "
                "typical of a packed loader or a shellcode-heavy implant.",
                {"process": name, "pid": pid}))
    return out


def rule_network(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        owner = as_text(field(row, "name")) or as_text(field(row, "owner"))
        lowner = owner.lower()
        pid = as_int(field(row, "pid"))
        faddr = as_text(field(row, "foreignaddr"))
        fport = as_int(field(row, "foreignport"))
        lport = as_int(field(row, "localport"))
        state = as_text(field(row, "state")).upper()
        proto = as_text(field(row, "proto")).upper()

        if fport in SUSPICIOUS_PORTS and _is_public_ip(faddr):
            out.append(_finding(
                "net.bad_port", "critical", "Network",
                f"{owner or 'process'} (PID {pid}) connects to {faddr}:{fport}",
                f"Port {fport} is associated with {SUSPICIOUS_PORTS[fport]}.", row,
                "Pivot on the remote address in your network telemetry."))
        elif lport in SUSPICIOUS_PORTS and "LISTEN" in state:
            out.append(_finding(
                "net.bad_listener", "high", "Network",
                f"{owner or 'process'} (PID {pid}) is listening on port {lport}",
                f"Port {lport} is associated with {SUSPICIOUS_PORTS[lport]}.", row))

        if lowner in NO_NETWORK_PROCS and (_is_public_ip(faddr) or "LISTEN" in state):
            out.append(_finding(
                "net.unexpected_owner", "high", "Network",
                f"{owner} (PID {pid}) holds a network endpoint "
                f"({faddr}:{fport} {state})",
                f"{owner} does not normally own network sockets. This is a strong "
                "indicator of injected code using the host process for egress.",
                row, "Check malfind and loaded modules for this PID."))

        if "LISTEN" in state and lport > 1024 and lowner not in (
                "svchost.exe", "system", "services.exe", "lsass.exe", "spoolsv.exe",
                "wininit.exe", "sshd", "nginx", "httpd", "apache2", "dockerd"):
            out.append(_finding(
                "net.high_listener", "low", "Network",
                f"{owner or 'process'} (PID {pid}) listens on {proto} port {lport}",
                "An unexpected high-numbered listener can be a backdoor or a "
                "developer tool. Worth a glance, not an alarm.", row))
    return out


def rule_dlls(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        keys = {k.lower(): v for k, v in row.items()}
        # ldrmodules-style triple list cross-check
        triple = [k for k in ("inload", "ininit", "inmem", "inloadorder",
                              "ininitorder", "inmemorder") if k in keys]
        if triple:
            missing = [k for k in triple if _truthy_false(keys[k])]
            path = as_text(field(row, "path"))
            if missing and not path.lower().endswith(".exe"):
                out.append(_finding(
                    "dll.unlinked", "high", "Module Hiding",
                    f"Module unlinked from {len(missing)} PEB list(s): "
                    f"{path or 'unknown path'}",
                    "Missing from: " + ", ".join(missing) +
                    ". Unlinking a module from the PEB lists hides it from most "
                    "user-mode enumeration.", row))
        path = as_text(field(row, "path"))
        if path and SUSPICIOUS_DIR_RE.search(path):
            out.append(_finding(
                "dll.suspicious_path", "medium", "Module Hiding",
                f"Module loaded from a user-writable directory: {path}",
                f"Loaded by {_pname(row)} (PID {as_int(field(row,'pid'))}).", row))
    return out


def rule_services(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        name = as_text(field(row, "name"))
        blob = " ".join(as_text(v) for v in row.values())
        binary = ""
        for key, value in row.items():
            if "binary" in key.lower() or "path" in key.lower() or key.lower() == "dumped":
                binary = as_text(value) or binary
        target = binary or blob
        low = target.lower()
        if SUSPICIOUS_DIR_RE.search(target):
            out.append(_finding(
                "svc.suspicious_path", "high", "Persistence",
                f"Service '{name}' runs a binary from a user-writable directory",
                f"Binary path: {binary or target[:300]}", row,
                "Service binaries should live under %SystemRoot% or Program Files."))
        if re.search(r"(cmd(\.exe)?\s|powershell|rundll32|regsvr32|mshta|wscript|cscript)",
                     low):
            out.append(_finding(
                "svc.script_host", "high", "Persistence",
                f"Service '{name}' launches a script host or LOLBin",
                f"Binary path: {binary or target[:300]}", row))
        if re.search(r"\\\?\?\\|\.tmp\b|\.dat\b", low) and "system32" not in low:
            out.append(_finding(
                "svc.odd_binary", "medium", "Persistence",
                f"Service '{name}' has an unusual binary path",
                f"Binary path: {binary or target[:300]}", row))
    return out


def rule_hooks(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        blob = " ".join(as_text(v) for v in row.values())
        low = blob.lower()
        module = as_text(field(row, "module")).lower()
        if "hooked" in low or "hook" in low and "unknown" in low:
            out.append(_finding(
                "kernel.hook", "critical", "Rootkit",
                "Hooked kernel structure detected",
                blob[:600], row,
                "Identify the owning driver and treat the host as compromised "
                "until proven otherwise."))
            continue
        if module in ("unknown", "", "-") and any(
                k.lower() in ("module", "owner", "driver") for k in row):
            out.append(_finding(
                "kernel.unknown_owner", "high", "Rootkit",
                "Kernel callback/entry with no owning module",
                blob[:600], row,
                "An entry whose target address does not resolve to a loaded "
                "driver usually means the driver was unloaded or hidden."))
    return out


def rule_kmodules(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        blob = " ".join(as_text(v) for v in row.values()).lower()
        if "hidden" in blob or "not in" in blob:
            out.append(_finding(
                "kernel.hidden_module", "critical", "Rootkit",
                "Hidden kernel module detected",
                " ".join(as_text(v) for v in row.values())[:600], row,
                "A module absent from the kernel's own module list is a rootkit "
                "until proven otherwise."))
        path = as_text(field(row, "path"))
        if path and SUSPICIOUS_DIR_RE.search(path):
            out.append(_finding(
                "kernel.module_path", "high", "Rootkit",
                f"Kernel module loaded from an unusual path: {path}", "", row))
    return out


def rule_threads(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        blob = " ".join(as_text(v) for v in row.values()).lower()
        if "unbacked" in blob or "unknown" in blob or "no module" in blob:
            out.append(_finding(
                "thread.unbacked", "high", "Code Injection",
                f"Thread with an unbacked start address in "
                f"{_pname(row) or 'a process'}",
                " ".join(as_text(v) for v in row.values())[:600], row,
                "Threads starting in memory that is not backed by a module are "
                "how injected code gets scheduled."))
    return out


def rule_registry(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        blob = " ".join(as_text(v) for v in row.values())
        if SUSPICIOUS_DIR_RE.search(blob):
            out.append(_finding(
                "reg.suspicious_value", "medium", "Persistence",
                "Registry value references a user-writable directory",
                blob[:600], row))
        low = blob.lower()
        if re.search(r"(powershell|mshta|rundll32|regsvr32|wscript|cscript|"
                     r"frombase64string|-enc\s)", low) and "run" in low:
            out.append(_finding(
                "reg.run_lolbin", "high", "Persistence",
                "Autorun value launches a script host or LOLBin",
                blob[:600], row))
    return out


def rule_bash(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        cmd = ""
        for key, value in row.items():
            if key.lower() in ("command", "cmd", "commandtime", "args"):
                if key.lower() != "commandtime":
                    cmd = as_text(value) or cmd
        if not cmd:
            cmd = " ".join(as_text(v) for v in row.values())
        low = cmd.lower()
        for pattern, severity, title in LOLBIN_PATTERNS:
            if re.search(pattern, low, re.I):
                out.append(_finding(
                    "bash." + re.sub(r"\W+", "_", title.lower())[:40],
                    severity, "Shell History",
                    f"{title} (shell history)", cmd[:1000], row))
    return out


def rule_console(rows, ctx) -> List[dict]:
    return rule_bash(rows, ctx)


def rule_credentials(rows, ctx) -> List[dict]:
    if not rows:
        return []
    return [_finding(
        "cred.material", "info", "Credentials",
        f"{len(rows)} credential record(s) recovered from memory",
        "Credential material was recoverable from this image. Treat every "
        "account listed as compromised and rotate the secrets.",
        rows[0] if rows else {},
        "Rotate the affected credentials before returning the host to service.")]


def rule_files(rows, ctx) -> List[dict]:
    out: List[dict] = []
    hits = 0
    for row in rows:
        path = as_text(field(row, "path")) or " ".join(
            as_text(v) for v in row.values())
        if SUSPICIOUS_DIR_RE.search(path) and re.search(
                r"\.(exe|dll|scr|ps1|bat|cmd|vbs|js|jar|hta|sys|elf|sh)\b", path, re.I):
            hits += 1
            if hits <= 25:
                out.append(_finding(
                    "file.staged_binary", "medium", "Staging",
                    f"Executable content in a user-writable path: {path[:200]}",
                    "", row))
    if hits > 25:
        out.append(_finding(
            "file.staged_many", "high", "Staging",
            f"{hits} executable files referenced from user-writable directories",
            "Only the first 25 are listed individually.", {}))
    return out


def rule_detection(rows, ctx) -> List[dict]:
    """For plugins that ARE the detector (hollowing, ghosting, ETW patching,
    unhooked syscalls, process spoofing): every row they return is the finding.
    We surface them rather than trying to re-derive the verdict."""
    out: List[dict] = []
    for row in rows[:200]:
        name = _pname(row) or as_text(field(row, "process"))
        pid = as_int(field(row, "pid"))
        detail = "  ".join(f"{k}={as_text(v)}" for k, v in row.items()
                           if as_text(v) not in ("", "None"))
        who = f"{name} (PID {pid})" if name else (f"PID {pid}" if pid >= 0 else "target")
        out.append(_finding(
            "detect.plugin_hit", "high", "Detection",
            f"Dedicated detection plugin flagged {who}",
            detail[:2000], row,
            "This plugin only emits rows when its specific technique is present — "
            "treat every row as a lead and confirm it against the process image."))
    return out


def rule_mutants(rows, ctx) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        name = as_text(field(row, "name"))
        if not name:
            continue
        if re.fullmatch(r"(Global\\|Local\\)?[A-Fa-f0-9\-]{16,}", name):
            out.append(_finding(
                "mutant.random", "low", "Malware Artefact",
                f"Mutex with a random/GUID-like name: {name[:120]}",
                "Many malware families create a hard-coded pseudo-random mutex to "
                "guarantee a single instance.", row))
    return out


RULES: Dict[str, Callable[[List[dict], dict], List[dict]]] = {
    "processes": rule_processes,
    "pstree": rule_processes,
    "process_scan": rule_process_scan,
    "psxview": rule_psxview,
    "cmdline": rule_cmdline,
    "console": rule_console,
    "malfind": rule_malfind,
    "network": rule_network,
    "dlls": rule_dlls,
    "services": rule_services,
    "hooks": rule_hooks,
    "kmodules": rule_kmodules,
    "drivers": rule_hooks,
    "threads": rule_threads,
    "registry": rule_registry,
    "bash": rule_bash,
    "credentials": rule_credentials,
    "files": rule_files,
    "mutants": rule_mutants,
    "detection": rule_detection,
}

MAX_ROWS = 60000
MAX_FINDINGS_PER_JOB = 400


def analyze(family: str, norm: Dict[str, Any],
            context: Dict[str, List[dict]] | None = None) -> List[dict]:
    """Run the rules for one plugin family. Never raises."""
    rule = RULES.get(family)
    if rule is None or norm.get("format") != "table":
        return []
    rows = to_dicts(norm, limit=MAX_ROWS)
    if not rows:
        return []
    try:
        findings = rule(rows, context or {})
    except Exception as exc:  # a broken rule must never fail a job
        return [_finding("triage.error", "info", "Engine",
                         f"Triage rule '{family}' failed", str(exc))]

    # de-duplicate identical (rule_id, title) pairs
    seen = set()
    unique = []
    for f in findings:
        key = (f["rule_id"], f["title"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda f: order.get(f["severity"], 9))
    return unique[:MAX_FINDINGS_PER_JOB]


def risk_score(findings) -> int:
    """0-100 risk score for an evidence item."""
    total = 0
    for f in findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity")
        state = f.state if hasattr(f, "state") else f.get("state", "open")
        if state == "dismissed":
            continue
        total += SEVERITY_SCORE.get(sev, 1)
    return min(100, total)


def risk_band(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "clean"

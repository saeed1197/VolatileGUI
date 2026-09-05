"""
Curated plugin catalog for both engines.

The runners also *discover* whatever plugins are actually installed
(`GET /plugins`).  This module supplies the human layer on top of that:
categories, plain-English descriptions, "popular plugin" flags, the canonical
`family` used by the parsers/triage engine, and the one-click presets.

Anything discovered at runtime but missing here is still selectable — it just
lands in the "Other" category with the engine's own docstring.
"""

from __future__ import annotations

from typing import Any, Dict, List

# name, label, category, os, family, popular, description
_VOL3: List[tuple] = [
    # ---- generic ----------------------------------------------------------
    ("banners.Banners", "Banners", "System", "generic", "sysinfo", True,
     "Scan for Linux/Mac kernel banner strings — the fastest way to identify a non-Windows image."),
    ("isfinfo.IsfInfo", "ISF Info", "System", "generic", "sysinfo", False,
     "List the symbol tables (ISF files) available to this engine."),
    ("frameworkinfo.FrameworkInfo", "Framework Info", "System", "generic", "sysinfo", False,
     "Show framework internals: available layers, symbol providers, versions."),
    ("timeliner.Timeliner", "Timeliner", "Timeline", "generic", "timeline", True,
     "Build a unified timeline from every plugin that exposes timestamps."),
    ("configwriter.ConfigWriter", "Config Writer", "Misc", "generic", "misc", False,
     "Dump the resolved analysis configuration as JSON."),
    ("layerwriter.LayerWriter", "Layer Writer", "Memory", "generic", "misc", False,
     "Write a memory layer out to a flat file (physical→virtual materialisation)."),
    ("regexscan.RegExScan", "RegEx Scan", "Malware", "generic", "strings", False,
     "Scan the whole image for a regular expression."),
    ("yarascan.YaraScan", "YARA Scan", "Malware", "generic", "yara", True,
     "Run YARA rules across the memory image."),
    ("vmscan.Vmscan", "VM Scan", "System", "generic", "misc", False,
     "Detect virtual machine monitor (hypervisor) structures in the image."),

    # ---- windows: system --------------------------------------------------
    ("windows.info.Info", "Image Info", "System", "windows", "sysinfo", True,
     "Kernel build, architecture, DTB, KUSER time — always run this first."),
    ("windows.statistics.Statistics", "Statistics", "System", "windows", "sysinfo", False,
     "Count valid/invalid pages across the layers — a quick image-integrity check."),
    ("windows.crashinfo.Crashinfo", "Crash Dump Info", "System", "windows", "sysinfo", False,
     "Header details for Windows crash dumps."),
    ("windows.sessions.Sessions", "Sessions", "System", "windows", "sessions", False,
     "Map processes to logon sessions and the user behind them."),
    ("windows.envars.Envars", "Environment Variables", "System", "windows", "envars", True,
     "Per-process environment variables — often reveals staging paths and proxies."),

    # ---- windows: processes ----------------------------------------------
    ("windows.pslist.PsList", "Process List", "Processes", "windows", "processes", True,
     "Walk the doubly-linked EPROCESS list — the standard process listing."),
    ("windows.psscan.PsScan", "Process Scan", "Processes", "windows", "process_scan", True,
     "Pool-scan for EPROCESS objects — finds unlinked (hidden) and exited processes."),
    ("windows.pstree.PsTree", "Process Tree", "Processes", "windows", "pstree", True,
     "Process list rendered as a parent/child tree — best view for spotting odd ancestry."),
    ("windows.cmdline.CmdLine", "Command Lines", "Processes", "windows", "cmdline", True,
     "Full command line of every process — the single highest-signal plugin for triage."),
    ("windows.dlllist.DllList", "Loaded DLLs", "Processes", "windows", "dlls", True,
     "Modules loaded into each process, with load paths."),
    ("windows.handles.Handles", "Handles", "Processes", "windows", "handles", False,
     "Open handles per process: files, keys, mutants, sections."),
    ("windows.getsids.GetSIDs", "Process SIDs", "Processes", "windows", "tokens", False,
     "The security identifiers attached to each process token."),
    ("windows.privileges.Privs", "Privileges", "Processes", "windows", "tokens", False,
     "Enabled/present token privileges — look for SeDebugPrivilege on odd processes."),
    ("windows.thrdscan.ThrdScan", "Thread Scan", "Processes", "windows", "threads", False,
     "Pool-scan for ETHREAD objects, including orphaned threads."),
    ("windows.threads.Threads", "Threads", "Processes", "windows", "threads", False,
     "Threads belonging to each process."),
    ("windows.suspicious_threads.SuspiciousThreads", "Suspicious Threads", "Malware",
     "windows", "threads", True,
     "Threads whose start address does not map to a loaded module — classic injection tell."),
    ("windows.psxview.PsXView", "Process Cross-View", "Malware", "windows", "psxview", True,
     "Compare several independent process-enumeration sources; a False column means "
     "the process is hidden from that view."),
    ("windows.hollowprocesses.HollowProcesses", "Hollow Processes", "Malware", "windows",
     "detection", True,
     "Detect process hollowing — a legitimate image replaced by injected code."),
    ("windows.processghosting.ProcessGhosting", "Process Ghosting", "Malware", "windows",
     "detection", True,
     "Detect process ghosting, where the backing file is deleted before the process starts."),
    ("windows.malware.pebmasquerade.PebMasquerade", "PEB Masquerade", "Malware", "windows",
     "detection", True,
     "Processes whose PEB image path disagrees with the real backing file."),
    ("windows.unhooked_system_calls.unhooked_system_calls", "Unhooked System Calls",
     "Malware", "windows", "detection", True,
     "Find ntdll stubs that no longer match the on-disk copy — EDR unhooking."),
    ("windows.etwpatch.EtwPatch", "ETW Patch", "Malware", "windows", "detection", True,
     "Detect in-memory patching of EtwEventWrite — a common telemetry-blinding step."),
    ("windows.suspended_threads.SuspendedThreads", "Suspended Threads", "Malware", "windows",
     "threads", False,
     "Threads left in a suspended state, as seen during injection and hollowing."),
    ("windows.debugregisters.DebugRegisters", "Debug Registers", "Malware", "windows",
     "detection", False,
     "Hardware breakpoints set via debug registers — used for stealthy hooking."),
    ("windows.svcdiff.SvcDiff", "Service Diff", "Persistence", "windows", "services", True,
     "Compare services found by scanning against the service list to reveal hidden ones."),
    ("windows.drivermodule.DriverModule", "Driver / Module Cross-View", "Kernel", "windows",
     "kmodules", True,
     "Correlate driver objects with loaded modules — mismatches indicate hidden drivers."),
    ("windows.cmdscan.CmdScan", "Console Command Scan", "Timeline", "windows", "console", True,
     "Recover commands typed into cmd.exe from the console history buffers."),
    ("windows.consoles.Consoles", "Console Output", "Timeline", "windows", "console", True,
     "Recover console input and output buffers, including command results."),
    ("windows.windowstations.WindowStations", "Window Stations", "Misc", "windows", "misc",
     False, "Window stations and the desktops they own."),
    ("windows.truecrypt.Passphrase", "TrueCrypt Passphrase", "Credentials", "windows",
     "credentials", False, "Recover cached TrueCrypt passphrases."),
    ("windows.getservicesids.GetServiceSIDs", "Service SIDs", "Registry", "windows",
     "registry", False, "Calculate the SID of each installed service."),
    ("windows.memmap.Memmap", "Memory Map", "Memory", "windows", "memmap", False,
     "Virtual→physical page mapping for a process; with --dump writes the address space."),

    # ---- windows: network -------------------------------------------------
    ("windows.netscan.NetScan", "Network Scan", "Network", "windows", "network", True,
     "Pool-scan for TCP/UDP endpoints and connections, including closed ones."),
    ("windows.netstat.NetStat", "Netstat", "Network", "windows", "network", True,
     "Walk the network tracking structures — the live connection table."),

    # ---- windows: malware -------------------------------------------------
    ("windows.malfind.Malfind", "Malfind", "Malware", "windows", "malfind", True,
     "Find private, executable, unbacked memory regions — injected code and shellcode."),
    ("windows.vadinfo.VadInfo", "VAD Info", "Malware", "windows", "vad", False,
     "Virtual address descriptors with protections and backing files."),
    ("windows.vadwalk.VadWalk", "VAD Walk", "Malware", "windows", "vad", False,
     "Raw walk of the VAD tree structure."),
    ("windows.vadyarascan.VadYaraScan", "VAD YARA Scan", "Malware", "windows", "yara", False,
     "Run YARA rules only inside process VADs (much faster than a full scan)."),
    ("windows.ldrmodules.LdrModules", "Ldr Modules", "Malware", "windows", "dlls", True,
     "Cross-check the three PEB module lists — unlinked entries mean DLL hiding."),
    ("windows.iat.IAT", "Import Address Table", "Malware", "windows", "hooks", False,
     "Enumerate IAT entries; mismatches indicate import hooking."),
    ("windows.pedump.PEDump", "PE Dump", "Malware", "windows", "files", False,
     "Dump a PE image (process or kernel module) back to disk."),
    ("windows.verinfo.VerInfo", "Version Info", "Malware", "windows", "modules", False,
     "PE version resources of loaded modules — unsigned/blank vendors stand out."),
    ("windows.strings.Strings", "Strings", "Malware", "windows", "strings", False,
     "Map a strings-file offset list back to processes."),

    # ---- windows: kernel --------------------------------------------------
    ("windows.modules.Modules", "Kernel Modules", "Kernel", "windows", "kmodules", True,
     "Loaded kernel drivers from the linked list."),
    ("windows.modscan.ModScan", "Module Scan", "Kernel", "windows", "kmodules", True,
     "Pool-scan for kernel modules — reveals unlinked/rootkit drivers."),
    ("windows.unloadedmodules.UnloadedModules", "Unloaded Modules", "Kernel", "windows",
     "kmodules", False, "Drivers that were loaded and then unloaded — anti-forensics trail."),
    ("windows.driverscan.DriverScan", "Driver Scan", "Kernel", "windows", "drivers", True,
     "Pool-scan for DRIVER_OBJECTs."),
    ("windows.driverirp.DriverIrp", "Driver IRP Hooks", "Kernel", "windows", "drivers", False,
     "IRP handler table per driver — hooked entries point outside the owning driver."),
    ("windows.devicetree.DeviceTree", "Device Tree", "Kernel", "windows", "drivers", False,
     "Driver/device stack — attached filter devices are visible here."),
    ("windows.ssdt.SSDT", "SSDT", "Kernel", "windows", "hooks", True,
     "System service descriptor table — entries not owned by ntoskrnl are hooks."),
    ("windows.callbacks.Callbacks", "Kernel Callbacks", "Kernel", "windows", "hooks", True,
     "Registered process/thread/image/registry notification callbacks."),
    ("windows.orphan_kernel_threads.Threads", "Orphan Kernel Threads", "Kernel", "windows",
     "threads", False, "Kernel threads with no owning module."),
    ("windows.bigpools.BigPools", "Big Pools", "Kernel", "windows", "pools", False,
     "Large kernel pool allocations by tag."),
    ("windows.poolscanner.PoolScanner", "Pool Scanner", "Kernel", "windows", "pools", False,
     "Generic pool tag scanner."),
    ("windows.mutantscan.MutantScan", "Mutant Scan", "Malware", "windows", "mutants", False,
     "Named mutexes — malware families are often identifiable by their mutex."),
    ("windows.symlinkscan.SymlinkScan", "Symlink Scan", "Misc", "windows", "misc", False,
     "Object-manager symbolic links."),
    ("windows.virtmap.VirtMap", "Virtual Map", "Memory", "windows", "misc", False,
     "Kernel virtual address ranges by usage."),

    # ---- windows: services / persistence ----------------------------------
    ("windows.svcscan.SvcScan", "Services", "Persistence", "windows", "services", True,
     "Installed Windows services with binary path, type and state."),
    ("windows.svclist.SvcList", "Service List", "Persistence", "windows", "services", False,
     "Services enumerated from the service record list."),
    ("windows.scheduled_tasks.ScheduledTasks", "Scheduled Tasks", "Persistence", "windows",
     "persistence", True, "Scheduled tasks recovered from memory."),
    ("windows.registry.amcache.Amcache", "Amcache", "Persistence", "windows", "registry", False,
     "Amcache execution evidence: paths, hashes, first-run times."),
    ("windows.shimcachemem.ShimcacheMem", "Shimcache", "Persistence", "windows",
     "registry", True, "Application compatibility cache — evidence of execution."),
    ("windows.registry.userassist.UserAssist", "UserAssist", "Persistence", "windows",
     "registry", True, "GUI programs the user launched, with run counts and timestamps."),

    # ---- windows: registry ------------------------------------------------
    ("windows.registry.hivelist.HiveList", "Hive List", "Registry", "windows", "registry", True,
     "Registry hives present in memory and their virtual offsets."),
    ("windows.registry.hivescan.HiveScan", "Hive Scan", "Registry", "windows", "registry", False,
     "Pool-scan for registry hives."),
    ("windows.registry.printkey.PrintKey", "Print Key", "Registry", "windows", "registry", True,
     "Print the values under a registry key (use --key, e.g. Microsoft\\Windows\\CurrentVersion\\Run)."),
    ("windows.registry.certificates.Certificates", "Certificates", "Registry", "windows",
     "registry", False, "Certificates stored in the registry hives."),
    ("windows.registry.getcellroutine.GetCellRoutine", "Get Cell Routine", "Registry",
     "windows", "registry", False, "Detect hooked registry cell routines."),

    # ---- windows: credentials --------------------------------------------
    ("windows.hashdump.Hashdump", "Hashdump", "Credentials", "windows", "credentials", True,
     "Dump local account NTLM hashes from the SAM hive."),
    ("windows.lsadump.Lsadump", "LSA Dump", "Credentials", "windows", "credentials", True,
     "Dump LSA secrets (service account passwords, cached material)."),
    ("windows.cachedump.Cachedump", "Cachedump", "Credentials", "windows", "credentials", False,
     "Dump cached domain credentials (MSCache)."),
    ("windows.skeleton_key_check.Skeleton_Key_Check", "Skeleton Key Check", "Credentials",
     "windows", "credentials", False,
     "Detect the Skeleton Key domain-controller backdoor."),

    # ---- windows: files ---------------------------------------------------
    ("windows.filescan.FileScan", "File Scan", "Files", "windows", "files", True,
     "Pool-scan for FILE_OBJECTs — every file path referenced in memory."),
    ("windows.dumpfiles.DumpFiles", "Dump Files", "Files", "windows", "files", False,
     "Extract cached file contents back to disk (use --virtaddr/--physaddr or --pid)."),
    ("windows.mftscan.MFTScan", "MFT Scan", "Files", "windows", "files", True,
     "Recover NTFS MFT records found in memory, with MACB timestamps."),
    ("windows.mftscan.ADS", "MFT Alternate Data Streams", "Files", "windows", "files", False,
     "Alternate data streams recovered from MFT records."),
    ("windows.mbrscan.MBRScan", "MBR Scan", "Files", "windows", "files", False,
     "Locate master boot records in memory (bootkit hunting)."),
    ("windows.cachedump.Cachedump", "Cachedump", "Credentials", "windows", "credentials", False,
     "Dump cached domain credentials."),

    # ---- linux ------------------------------------------------------------
    ("linux.pslist.PsList", "Process List", "Processes", "linux", "processes", True,
     "Task list walked from init_task."),
    ("linux.pstree.PsTree", "Process Tree", "Processes", "linux", "pstree", True,
     "Task list as a parent/child tree."),
    ("linux.psscan.PsScan", "Process Scan", "Processes", "linux", "process_scan", True,
     "Scan for task_struct objects — catches unlinked processes."),
    ("linux.psaux.PsAux", "Process Args", "Processes", "linux", "cmdline", True,
     "Full argv of every task — the Linux equivalent of cmdline."),
    ("linux.bash.Bash", "Bash History", "Timeline", "linux", "bash", True,
     "Recover bash history (with timestamps) straight out of shell memory."),
    ("linux.envars.Envars", "Environment Variables", "System", "linux", "envars", False,
     "Per-task environment variables."),
    ("linux.lsof.Lsof", "Open Files", "Processes", "linux", "handles", True,
     "Open file descriptors per task."),
    ("linux.sockstat.Sockstat", "Socket Stats", "Network", "linux", "network", True,
     "Open sockets per task with protocol, state and endpoints."),
    ("linux.ip.Addr", "IP Addresses", "Network", "linux", "network", False,
     "Configured network addresses."),
    ("linux.ip.Link", "IP Links", "Network", "linux", "network", False,
     "Network interfaces and their state (promiscuous mode is visible here)."),
    ("linux.lsmod.Lsmod", "Kernel Modules", "Kernel", "linux", "kmodules", True,
     "Loaded kernel modules."),
    ("linux.hidden_modules.Hidden_modules", "Hidden Modules", "Kernel", "linux", "kmodules", True,
     "Modules removed from the module list — LKM rootkits."),
    ("linux.check_modules.Check_modules", "Check Modules", "Kernel", "linux", "hooks", True,
     "Compare the module list against sysfs to spot hidden modules."),
    ("linux.check_syscall.Check_syscall", "Check Syscall Table", "Kernel", "linux", "hooks", True,
     "Syscall table entries pointing outside the kernel — syscall hooking."),
    ("linux.check_afinfo.Check_afinfo", "Check afinfo", "Kernel", "linux", "hooks", False,
     "Network protocol operation structures that have been tampered with."),
    ("linux.check_idt.Check_idt", "Check IDT", "Kernel", "linux", "hooks", False,
     "Interrupt descriptor table hooks."),
    ("linux.check_creds.Check_creds", "Check Creds", "Kernel", "linux", "tokens", False,
     "Processes sharing credential structures — a classic privilege-escalation rootkit trick."),
    ("linux.capabilities.Capabilities", "Capabilities", "Processes", "linux", "tokens", False,
     "Linux capability sets per task."),
    ("linux.malfind.Malfind", "Malfind", "Malware", "linux", "malfind", True,
     "Anonymous executable memory regions — injected code."),
    ("linux.elfs.Elfs", "ELFs in Memory", "Malware", "linux", "modules", False,
     "ELF binaries mapped into process memory."),
    ("linux.library_list.LibraryList", "Loaded Libraries", "Processes", "linux", "dlls", False,
     "Shared libraries loaded per process."),
    ("linux.proc.Maps", "Process Maps", "Memory", "linux", "vad", False,
     "The /proc/<pid>/maps view for each task."),
    ("linux.vmayarascan.VmaYaraScan", "VMA YARA Scan", "Malware", "linux", "yara", False,
     "YARA scan restricted to process VMAs."),
    ("linux.tty_check.tty_check", "TTY Check", "Kernel", "linux", "hooks", False,
     "Hooked terminal operation structures — keystroke logging."),
    ("linux.keyboard_notifiers.Keyboard_notifiers", "Keyboard Notifiers", "Kernel", "linux",
     "hooks", False, "Registered keyboard notifier callbacks (keyloggers)."),
    ("linux.kmsg.Kmsg", "Kernel Ring Buffer", "System", "linux", "logs", True,
     "dmesg contents recovered from memory."),
    ("linux.mountinfo.MountInfo", "Mounts", "System", "linux", "misc", False,
     "Mounted filesystems per namespace."),
    ("linux.iomem.IOMem", "IO Memory", "System", "linux", "misc", False,
     "The /proc/iomem resource tree."),
    ("linux.boottime.Boottime", "Boot Time", "System", "linux", "sysinfo", False,
     "System boot time."),
    ("linux.kthreads.Kthreads", "Kernel Threads", "Kernel", "linux", "threads", False,
     "Kernel thread list with their entry points."),
    ("linux.pagecache.Files", "Page Cache Files", "Files", "linux", "files", False,
     "Files present in the page cache."),
    ("linux.pagecache.InodePages", "Inode Pages", "Files", "linux", "files", False,
     "Cached pages for a given inode (recoverable file content)."),
    ("linux.ebpf.EBPF", "eBPF Programs", "Kernel", "linux", "misc", False,
     "Loaded eBPF programs — an increasingly popular rootkit vector."),
    ("linux.malware.process_spoofing.ProcessSpoofing", "Process Spoofing", "Malware", "linux",
     "detection", True,
     "Tasks whose argv has been rewritten to impersonate another process."),
    ("linux.malware.modxview.Modxview", "Module Cross-View", "Kernel", "linux", "kmodules",
     True, "Compare every module-enumeration source to surface hidden LKMs."),
    ("linux.netfilter.Netfilter", "Netfilter Hooks", "Kernel", "linux", "hooks", True,
     "Registered netfilter hooks — how a rootkit hides or redirects traffic."),
    ("linux.tracing.ftrace.CheckFtrace", "Check ftrace", "Kernel", "linux", "hooks", True,
     "ftrace hooks, the most common modern Linux kernel-hooking technique."),
    ("linux.tracing.tracepoints.CheckTracepoints", "Check Tracepoints", "Kernel", "linux",
     "hooks", False, "Kernel tracepoint callbacks that have been hijacked."),
    ("linux.ptrace.Ptrace", "Ptrace", "Processes", "linux", "misc", False,
     "Tasks currently being ptrace'd — injection and debugging."),
    ("linux.pscallstack.PsCallStack", "Process Call Stacks", "Processes", "linux", "misc",
     False, "Kernel call stack of each task."),
    ("linux.kallsyms.Kallsyms", "Kallsyms", "Kernel", "linux", "kmodules", False,
     "Kernel symbol table, including symbols added by loaded modules."),
    ("linux.sockscan.Sockscan", "Socket Scan", "Network", "linux", "network", False,
     "Pool-scan for socket objects, including ones no longer linked to a task."),
    ("linux.vmaregexscan.VmaRegExScan", "VMA RegEx Scan", "Malware", "linux", "strings", False,
     "Scan process memory regions for a regular expression."),

    # ---- mac ---------------------------------------------------------------
    ("mac.pslist.PsList", "Process List", "Processes", "mac", "processes", True,
     "Process list for macOS images."),
    ("mac.pstree.PsTree", "Process Tree", "Processes", "mac", "pstree", True,
     "Process tree for macOS images."),
    ("mac.psaux.Psaux", "Process Args", "Processes", "mac", "cmdline", True,
     "Command line arguments per process."),
    ("mac.lsof.Lsof", "Open Files", "Processes", "mac", "handles", False,
     "Open file descriptors per process."),
    ("mac.netstat.Netstat", "Netstat", "Network", "mac", "network", True,
     "Active network connections."),
    ("mac.malfind.Malfind", "Malfind", "Malware", "mac", "malfind", True,
     "Injected/anonymous executable memory."),
    ("mac.lsmod.Lsmod", "Kernel Extensions", "Kernel", "mac", "kmodules", True,
     "Loaded kernel extensions (kexts)."),
    ("mac.check_syscall.Check_syscall", "Check Syscall", "Kernel", "mac", "hooks", False,
     "Hooked syscall table entries."),
    ("mac.bash.Bash", "Bash History", "Timeline", "mac", "bash", False,
     "Recovered bash history."),
    ("mac.ifconfig.Ifconfig", "Ifconfig", "Network", "mac", "network", False,
     "Network interface configuration."),
]

_VOL2: List[tuple] = [
    # ---- system -----------------------------------------------------------
    ("imageinfo", "Image Info", "System", "windows", "sysinfo", True,
     "Identify the image and suggest profiles. Run this before anything else."),
    ("kdbgscan", "KDBG Scan", "System", "windows", "sysinfo", True,
     "Find the kernel debugger block — more precise than imageinfo when profiles are ambiguous."),
    ("kpcrscan", "KPCR Scan", "System", "windows", "sysinfo", False,
     "Locate per-CPU KPCR structures."),
    ("crashinfo", "Crash Dump Info", "System", "windows", "sysinfo", False,
     "Windows crash dump header details."),
    ("hibinfo", "Hibernation Info", "System", "windows", "sysinfo", False,
     "Hibernation file header details."),
    ("machoinfo", "Mach-O Info", "System", "mac", "sysinfo", False,
     "Mach-O header info for macOS memory samples."),

    # ---- processes ---------------------------------------------------------
    ("pslist", "Process List", "Processes", "windows", "processes", True,
     "Walk the EPROCESS linked list — the standard process listing."),
    ("psscan", "Process Scan", "Processes", "windows", "process_scan", True,
     "Pool-scan for EPROCESS — reveals hidden and terminated processes."),
    ("pstree", "Process Tree", "Processes", "windows", "pstree", True,
     "Processes rendered as a parent/child tree."),
    ("psxview", "Process Cross-View", "Malware", "windows", "psxview", True,
     "Compare seven process-enumeration sources; a False column is a hiding indicator."),
    ("pstotal", "Process Total", "Processes", "windows", "processes", False,
     "Combined pslist/psscan/pstree view."),
    ("cmdline", "Command Lines", "Processes", "windows", "cmdline", True,
     "Process command lines — the highest-signal single plugin for triage."),
    ("cmdscan", "Console Command Scan", "Timeline", "windows", "console", True,
     "Recover commands typed into cmd.exe from the console history buffers."),
    ("consoles", "Console Output", "Timeline", "windows", "console", True,
     "Recover full console input *and* output, including screen buffers."),
    ("dlllist", "Loaded DLLs", "Processes", "windows", "dlls", True,
     "DLLs loaded per process, with full paths and load counts."),
    ("dlldump", "Dump DLLs", "Files", "windows", "files", False,
     "Extract loaded DLLs back to disk."),
    ("handles", "Handles", "Processes", "windows", "handles", False,
     "Open handles per process."),
    ("getsids", "Process SIDs", "Processes", "windows", "tokens", False,
     "Security identifiers of each process."),
    ("privs", "Privileges", "Processes", "windows", "tokens", False,
     "Token privileges present/enabled per process."),
    ("envars", "Environment Variables", "System", "windows", "envars", True,
     "Per-process environment blocks."),
    ("verinfo", "Version Info", "Malware", "windows", "modules", False,
     "PE version resources of mapped modules."),
    ("enumfunc", "Enumerate Functions", "Malware", "windows", "hooks", False,
     "Enumerate imports and exports of modules."),
    ("threads", "Threads", "Processes", "windows", "threads", False,
     "Thread objects with tags and start addresses."),
    ("thrdscan", "Thread Scan", "Processes", "windows", "threads", False,
     "Pool-scan for ETHREAD objects."),
    ("procdump", "Dump Process", "Files", "windows", "files", False,
     "Dump a process executable back to disk (use --pid)."),
    ("memdump", "Dump Process Memory", "Memory", "windows", "memmap", False,
     "Dump the addressable memory of a process (use --pid)."),
    ("memmap", "Memory Map", "Memory", "windows", "memmap", False,
     "Virtual→physical mapping for a process."),

    # ---- network -----------------------------------------------------------
    ("netscan", "Network Scan", "Network", "windows", "network", True,
     "Pool-scan for network objects (Vista+ images)."),
    ("connections", "Connections", "Network", "windows", "network", True,
     "Active TCP connections (XP/2003 images)."),
    ("connscan", "Connection Scan", "Network", "windows", "network", False,
     "Pool-scan for connection objects, including closed ones (XP/2003)."),
    ("sockets", "Sockets", "Network", "windows", "network", True,
     "Open sockets (XP/2003 images)."),
    ("sockscan", "Socket Scan", "Network", "windows", "network", False,
     "Pool-scan for socket objects (XP/2003)."),

    # ---- malware -----------------------------------------------------------
    ("malfind", "Malfind", "Malware", "windows", "malfind", True,
     "Private RWX memory with no backing file — injected code and shellcode."),
    ("ldrmodules", "Ldr Modules", "Malware", "windows", "dlls", True,
     "Cross-check the three PEB module lists — a False means the DLL was unlinked."),
    ("apihooks", "API Hooks", "Malware", "windows", "hooks", True,
     "Inline/IAT/EAT hooks in user and kernel space."),
    ("hollowfind", "Hollow Find", "Malware", "windows", "malfind", False,
     "Detect process hollowing (community plugin — needs --plugins)."),
    ("yarascan", "YARA Scan", "Malware", "windows", "yara", True,
     "Scan process and kernel memory with YARA rules."),
    ("vadinfo", "VAD Info", "Malware", "windows", "vad", False,
     "Virtual address descriptors with protection flags."),
    ("vadtree", "VAD Tree", "Malware", "windows", "vad", False,
     "VAD structures rendered as a tree."),
    ("vadwalk", "VAD Walk", "Malware", "windows", "vad", False,
     "Flat walk of the VAD tree."),
    ("vaddump", "VAD Dump", "Memory", "windows", "vad", False,
     "Dump each VAD region to a file."),
    ("impscan", "Import Scan", "Malware", "windows", "hooks", False,
     "Rebuild the import table of an unpacked/injected module."),
    ("svcscan", "Services", "Persistence", "windows", "services", True,
     "Windows services with binary paths and state."),
    ("servicediff", "Service Diff", "Persistence", "windows", "services", False,
     "Compare services in memory against the registry to find hidden ones."),

    # ---- kernel ------------------------------------------------------------
    ("modules", "Kernel Modules", "Kernel", "windows", "kmodules", True,
     "Loaded kernel drivers from the module list."),
    ("modscan", "Module Scan", "Kernel", "windows", "kmodules", True,
     "Pool-scan for kernel modules — finds unlinked drivers."),
    ("moddump", "Dump Module", "Files", "windows", "files", False,
     "Dump a kernel driver to disk."),
    ("unloadedmodules", "Unloaded Modules", "Kernel", "windows", "kmodules", False,
     "Drivers that have been unloaded."),
    ("driverscan", "Driver Scan", "Kernel", "windows", "drivers", True,
     "Pool-scan for DRIVER_OBJECTs."),
    ("driverirp", "Driver IRP Hooks", "Kernel", "windows", "drivers", True,
     "IRP dispatch tables — entries outside the owning driver are hooks."),
    ("devicetree", "Device Tree", "Kernel", "windows", "drivers", False,
     "Driver/device attachment stack."),
    ("ssdt", "SSDT", "Kernel", "windows", "hooks", True,
     "System service descriptor table hook detection."),
    ("callbacks", "Kernel Callbacks", "Kernel", "windows", "hooks", True,
     "Notification routines registered with the kernel."),
    ("idt", "IDT", "Kernel", "windows", "hooks", False,
     "Interrupt descriptor table entries."),
    ("gdt", "GDT", "Kernel", "windows", "hooks", False,
     "Global descriptor table entries (call gate detection)."),
    ("timers", "Kernel Timers", "Kernel", "windows", "hooks", False,
     "Registered kernel timers and their DPC routines."),
    ("bigpools", "Big Pools", "Kernel", "windows", "pools", False,
     "Large kernel pool allocations by tag."),
    ("mutantscan", "Mutant Scan", "Malware", "windows", "mutants", False,
     "Named mutexes — often a malware family fingerprint."),
    ("symlinkscan", "Symlink Scan", "Misc", "windows", "misc", False,
     "Object manager symbolic links."),
    ("atomscan", "Atom Scan", "Misc", "windows", "misc", False,
     "Atom tables — injected DLL names frequently show up here."),
    ("atoms", "Atoms", "Misc", "windows", "misc", False,
     "Session/window-station atom tables."),

    # ---- registry ----------------------------------------------------------
    ("hivelist", "Hive List", "Registry", "windows", "registry", True,
     "Registry hives in memory with their virtual addresses."),
    ("hivescan", "Hive Scan", "Registry", "windows", "registry", False,
     "Pool-scan for registry hives."),
    ("printkey", "Print Key", "Registry", "windows", "registry", True,
     "Print subkeys/values of a key (use -K 'Microsoft\\Windows\\CurrentVersion\\Run')."),
    ("hivedump", "Hive Dump", "Registry", "windows", "registry", False,
     "Recursively dump an entire hive."),
    ("userassist", "UserAssist", "Persistence", "windows", "registry", True,
     "GUI program execution counts and last-run times."),
    ("shellbags", "Shellbags", "Persistence", "windows", "registry", False,
     "Folder access history from shellbag registry data."),
    ("shimcache", "Shimcache", "Persistence", "windows", "registry", True,
     "Application compatibility cache — evidence of execution."),
    ("amcache", "Amcache", "Persistence", "windows", "registry", False,
     "Amcache entries: path, SHA1, first execution."),
    ("auditpol", "Audit Policy", "Registry", "windows", "registry", False,
     "The system audit policy from the registry."),
    ("getservicesids", "Service SIDs", "Registry", "windows", "registry", False,
     "Calculate service SIDs from the registry."),
    ("dumpregistry", "Dump Registry", "Registry", "windows", "registry", False,
     "Write registry hives out to disk."),

    # ---- credentials --------------------------------------------------------
    ("hashdump", "Hashdump", "Credentials", "windows", "credentials", True,
     "Local account NTLM hashes from SAM/SYSTEM."),
    ("lsadump", "LSA Dump", "Credentials", "windows", "credentials", True,
     "LSA secrets."),
    ("cachedump", "Cachedump", "Credentials", "windows", "credentials", False,
     "Cached domain credentials."),
    ("truecryptmaster", "TrueCrypt Master Keys", "Credentials", "windows", "credentials", False,
     "Recover TrueCrypt master keys from memory."),
    ("truecryptpassphrase", "TrueCrypt Passphrase", "Credentials", "windows", "credentials",
     False, "Recover cached TrueCrypt passphrases."),

    # ---- files / artefacts --------------------------------------------------
    ("filescan", "File Scan", "Files", "windows", "files", True,
     "Pool-scan for FILE_OBJECTs — every file path in memory."),
    ("dumpfiles", "Dump Files", "Files", "windows", "files", False,
     "Extract cached file contents to disk."),
    ("mftparser", "MFT Parser", "Files", "windows", "files", True,
     "Recover NTFS MFT entries with MACB timestamps."),
    ("mbrparser", "MBR Parser", "Files", "windows", "files", False,
     "Parse master boot records found in memory."),
    ("evtlogs", "Event Logs", "Timeline", "windows", "logs", True,
     "Recover Windows XP/2003 .evt event log records."),
    ("iehistory", "IE History", "Timeline", "windows", "logs", True,
     "Recover Internet Explorer / WinINet cache and history records."),
    ("notepad", "Notepad Contents", "Misc", "windows", "misc", False,
     "Recover the text currently open in Notepad."),
    ("clipboard", "Clipboard", "Misc", "windows", "misc", True,
     "Recover clipboard contents — frequently holds pasted credentials."),
    ("screenshot", "Screenshot", "Misc", "windows", "misc", False,
     "Reconstruct a wireframe screenshot of the desktop from GDI structures."),
    ("editbox", "Edit Boxes", "Misc", "windows", "misc", False,
     "Recover the text inside GUI edit controls."),
    ("timeliner", "Timeliner", "Timeline", "windows", "timeline", True,
     "Aggregate every timestamped artefact into one timeline."),
    ("sessions", "Sessions", "System", "windows", "sessions", False,
     "Logon sessions and their processes."),
    ("deskscan", "Desktop Scan", "Misc", "windows", "misc", False,
     "Desktop objects and their threads."),
    ("wndscan", "Window Station Scan", "Misc", "windows", "misc", False,
     "Window stations and clipboard ownership."),
    ("messagehooks", "Message Hooks", "Malware", "windows", "hooks", False,
     "Installed Windows message hooks (SetWindowsHookEx)."),
    ("eventhooks", "Event Hooks", "Malware", "windows", "hooks", False,
     "Installed window event hooks."),
    ("gahti", "GAHTI", "Misc", "windows", "misc", False,
     "Global window handle type information."),

    # ---- linux ---------------------------------------------------------------
    ("linux_pslist", "Process List", "Processes", "linux", "processes", True,
     "Task list walked from init_task."),
    ("linux_pstree", "Process Tree", "Processes", "linux", "pstree", True,
     "Task list as a parent/child tree."),
    ("linux_psaux", "Process Args", "Processes", "linux", "cmdline", True,
     "Full argv per task."),
    ("linux_psxview", "Process Cross-View", "Malware", "linux", "psxview", True,
     "Compare process enumeration sources to find hidden tasks."),
    ("linux_pslist_cache", "Process List (cache)", "Processes", "linux", "processes", False,
     "Tasks recovered from the kmem_cache allocator."),
    ("linux_pidhashtable", "PID Hash Table", "Processes", "linux", "processes", False,
     "Tasks enumerated from the PID hash table."),
    ("linux_bash", "Bash History", "Timeline", "linux", "bash", True,
     "Recover bash history from shell memory."),
    ("linux_bash_env", "Bash Environment", "System", "linux", "envars", False,
     "Environment variables of shell processes."),
    ("linux_netstat", "Netstat", "Network", "linux", "network", True,
     "Open sockets per task."),
    ("linux_ifconfig", "Ifconfig", "Network", "linux", "network", False,
     "Interfaces and addresses; flags reveal promiscuous mode."),
    ("linux_arp", "ARP Cache", "Network", "linux", "network", False,
     "The kernel ARP table."),
    ("linux_route_cache", "Route Cache", "Network", "linux", "network", False,
     "Cached routing entries."),
    ("linux_lsof", "Open Files", "Processes", "linux", "handles", True,
     "Open file descriptors per task."),
    ("linux_lsmod", "Kernel Modules", "Kernel", "linux", "kmodules", True,
     "Loaded kernel modules."),
    ("linux_hidden_modules", "Hidden Modules", "Kernel", "linux", "kmodules", True,
     "Modules removed from the module list."),
    ("linux_check_modules", "Check Modules", "Kernel", "linux", "hooks", True,
     "Compare module list against sysfs."),
    ("linux_check_syscall", "Check Syscall Table", "Kernel", "linux", "hooks", True,
     "Detect syscall table hooking."),
    ("linux_check_afinfo", "Check afinfo", "Kernel", "linux", "hooks", False,
     "Tampered network protocol operation structures."),
    ("linux_check_creds", "Check Creds", "Kernel", "linux", "tokens", False,
     "Processes sharing cred structures."),
    ("linux_check_idt", "Check IDT", "Kernel", "linux", "hooks", False,
     "IDT hook detection."),
    ("linux_check_tty", "Check TTY", "Kernel", "linux", "hooks", False,
     "Hooked terminal receive handlers (keyloggers)."),
    ("linux_keyboard_notifiers", "Keyboard Notifiers", "Kernel", "linux", "hooks", False,
     "Registered keyboard notifier callbacks."),
    ("linux_malfind", "Malfind", "Malware", "linux", "malfind", True,
     "Anonymous executable memory mappings."),
    ("linux_proc_maps", "Process Maps", "Memory", "linux", "vad", False,
     "The /proc/<pid>/maps view per task."),
    ("linux_library_list", "Loaded Libraries", "Processes", "linux", "dlls", False,
     "Shared libraries per process."),
    ("linux_enumerate_files", "Enumerate Files", "Files", "linux", "files", False,
     "Files referenced by the dentry cache."),
    ("linux_find_file", "Find/Recover File", "Files", "linux", "files", False,
     "Locate and extract a cached file by path or inode."),
    ("linux_dentry_cache", "Dentry Cache", "Files", "linux", "files", False,
     "File paths recoverable from the dentry cache."),
    ("linux_mount", "Mounts", "System", "linux", "misc", False,
     "Mounted filesystems."),
    ("linux_dmesg", "Kernel Ring Buffer", "System", "linux", "logs", True,
     "dmesg output recovered from memory."),
    ("linux_cpuinfo", "CPU Info", "System", "linux", "sysinfo", False,
     "Per-CPU information."),
    ("linux_yarascan", "YARA Scan", "Malware", "linux", "yara", False,
     "YARA scan of task or kernel memory."),

    # ---- mac -----------------------------------------------------------------
    ("mac_pslist", "Process List", "Processes", "mac", "processes", True,
     "Process list for macOS images."),
    ("mac_pstree", "Process Tree", "Processes", "mac", "pstree", True,
     "Process tree for macOS images."),
    ("mac_psaux", "Process Args", "Processes", "mac", "cmdline", True,
     "Command line arguments per process."),
    ("mac_psxview", "Process Cross-View", "Malware", "mac", "psxview", False,
     "Compare process sources to find hidden processes."),
    ("mac_netstat", "Netstat", "Network", "mac", "network", True,
     "Active network connections."),
    ("mac_lsof", "Open Files", "Processes", "mac", "handles", False,
     "Open file descriptors per process."),
    ("mac_malfind", "Malfind", "Malware", "mac", "malfind", True,
     "Injected/anonymous executable memory."),
    ("mac_lsmod", "Kernel Extensions", "Kernel", "mac", "kmodules", True,
     "Loaded kexts."),
    ("mac_bash", "Bash History", "Timeline", "mac", "bash", False,
     "Recovered bash history."),
    ("mac_check_syscall", "Check Syscall", "Kernel", "mac", "hooks", False,
     "Syscall table hook detection."),
    ("mac_ifconfig", "Ifconfig", "Network", "mac", "network", False,
     "Network interface configuration."),
    ("mac_dump_file", "Dump File", "Files", "mac", "files", False,
     "Extract a cached file."),
]

CATEGORY_ORDER = [
    "System", "Processes", "Network", "Malware", "Kernel", "Persistence",
    "Registry", "Credentials", "Files", "Timeline", "Memory", "Misc", "Other",
]

# Values are keys into the inline SVG icon set (see templating.icon).
CATEGORY_ICONS = {
    "System": "gear", "Processes": "layout", "Network": "exchange",
    "Malware": "bug", "Kernel": "cpu", "Persistence": "anchor",
    "Registry": "list", "Credentials": "key", "Files": "file",
    "Timeline": "clock", "Memory": "layers", "Misc": "sparkle", "Other": "dot",
}


def _build(rows: List[tuple], engine: str) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for name, label, category, os_name, family, popular, desc in rows:
        out.setdefault(name, {
            "name": name, "label": label, "category": category, "os": os_name,
            "family": family, "popular": bool(popular), "description": desc,
            "engine": engine, "curated": True, "args": ARG_SPECS.get(name, []),
        })
    return out


# Optional per-plugin arguments the UI renders as form fields.
ARG_SPECS: Dict[str, List[dict]] = {
    # vol3
    "windows.pslist.PsList": [
        {"flag": "pid", "label": "PID filter", "type": "text",
         "help": "Comma-separated PIDs"},
        {"flag": "dump", "label": "Dump process executables", "type": "bool"},
    ],
    "windows.dlllist.DllList": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump", "label": "Dump DLLs", "type": "bool"},
    ],
    "windows.malfind.Malfind": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump", "label": "Dump injected regions", "type": "bool"},
    ],
    "windows.handles.Handles": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
    ],
    "windows.cmdline.CmdLine": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
    ],
    "windows.registry.printkey.PrintKey": [
        {"flag": "key", "label": "Registry key", "type": "text", "required": True,
         "placeholder": "Microsoft\\Windows\\CurrentVersion\\Run"},
        {"flag": "recurse", "label": "Recurse subkeys", "type": "bool"},
    ],
    "windows.memmap.Memmap": [
        {"flag": "pid", "label": "PID", "type": "text", "required": True},
        {"flag": "dump", "label": "Dump address space", "type": "bool"},
    ],
    "windows.dumpfiles.DumpFiles": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "virtaddr", "label": "Virtual offset", "type": "text"},
        {"flag": "physaddr", "label": "Physical offset", "type": "text"},
    ],
    "windows.pedump.PEDump": [
        {"flag": "base", "label": "Base address", "type": "text", "required": True,
         "placeholder": "0x... — from windows.pslist / windows.modules / windows.dlllist"},
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "kernel-module", "label": "Base is a kernel module (not a process)",
         "type": "bool"},
    ],
    "windows.strings.Strings": [
        {"flag": "strings-file", "label": "Strings file (path in container)", "type": "text",
         "required": True,
         "placeholder": "/evidence/strings.txt — output of `strings -a -t d memdump.mem`"},
        {"flag": "pid", "label": "PID filter", "type": "text"},
    ],
    "windows.vadinfo.VadInfo": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump", "label": "Dump VADs", "type": "bool"},
    ],
    "yarascan.YaraScan": [
        {"flag": "yara-rules", "label": "Inline YARA rule / string", "type": "text",
         "placeholder": "/rules/apt.yar or a raw string"},
        {"flag": "yara-file", "label": "YARA rules file (path in container)", "type": "text"},
    ],
    "windows.vadyarascan.VadYaraScan": [
        {"flag": "yara-file", "label": "YARA rules file", "type": "text"},
        {"flag": "pid", "label": "PID filter", "type": "text"},
    ],
    "regexscan.RegExScan": [
        {"flag": "pattern", "label": "Regular expression", "type": "text", "required": True},
    ],
    "windows.vadregexscan.VadRegExScan": [
        {"flag": "pattern", "label": "Regular expression", "type": "text", "required": True},
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "maxsize", "label": "Max region size (bytes)", "type": "text"},
    ],
    "windows.pe_symbols.PESymbols": [
        {"flag": "source", "label": "Source", "type": "text", "required": True,
         "placeholder": "kernel or processes"},
        {"flag": "module", "label": "Module name", "type": "text", "required": True,
         "placeholder": "e.g. ntoskrnl or explorer.exe"},
        {"flag": "symbols", "label": "Symbol names (space-separated)", "type": "text"},
        {"flag": "addresses", "label": "Addresses (space-separated)", "type": "text"},
    ],
    "linux.pslist.PsList": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump", "label": "Dump task executables", "type": "bool"},
    ],
    "linux.malfind.Malfind": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump", "label": "Dump regions", "type": "bool"},
    ],
    # vol2
    "pslist": [{"flag": "pid", "label": "PID filter", "type": "text"}],
    "dlllist": [{"flag": "pid", "label": "PID filter", "type": "text"}],
    "malfind": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump-dir", "label": "Dump directory", "type": "text",
         "placeholder": "/artifacts"},
    ],
    "handles": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "object-type", "label": "Object type", "type": "text",
         "placeholder": "Mutant / File / Key"},
    ],
    "printkey": [
        {"flag": "K", "label": "Registry key", "type": "text", "required": True,
         "placeholder": "Microsoft\\Windows\\CurrentVersion\\Run"},
    ],
    "procdump": [
        {"flag": "pid", "label": "PID", "type": "text", "required": True},
        {"flag": "dump-dir", "label": "Dump directory", "type": "text",
         "placeholder": "/artifacts"},
    ],
    "memdump": [
        {"flag": "pid", "label": "PID", "type": "text", "required": True},
        {"flag": "dump-dir", "label": "Dump directory", "type": "text",
         "placeholder": "/artifacts"},
    ],
    "dumpfiles": [
        {"flag": "pid", "label": "PID filter", "type": "text"},
        {"flag": "dump-dir", "label": "Dump directory", "type": "text",
         "placeholder": "/artifacts"},
        {"flag": "regex", "label": "Filename regex", "type": "text"},
    ],
    "yarascan": [
        {"flag": "yara-rules", "label": "Inline YARA string", "type": "text"},
        {"flag": "yara-file", "label": "YARA rules file", "type": "text"},
        {"flag": "pid", "label": "PID filter", "type": "text"},
    ],
    "linux_bash": [{"flag": "pid", "label": "PID filter", "type": "text"}],
    "linux_find_file": [
        {"flag": "F", "label": "File path", "type": "text"},
        {"flag": "O", "label": "Output file", "type": "text"},
    ],
}

CATALOG: Dict[str, Dict[str, dict]] = {
    "vol3": _build(_VOL3, "vol3"),
    "vol2": _build(_VOL2, "vol2"),
}


# ---------------------------------------------------------------------------
# Presets — the "popular plugins" one-click sets
# ---------------------------------------------------------------------------
PRESETS: Dict[str, dict] = {
    "quick_triage": {
        "key": "quick_triage",
        "label": "Quick Triage",
        "icon": "zap",
        "blurb": "The five-minute answer: who ran what, from where, talking to whom.",
        "plugins": {
            "vol3": {
                "windows": ["windows.info.Info", "windows.pslist.PsList",
                            "windows.pstree.PsTree", "windows.cmdline.CmdLine",
                            "windows.netscan.NetScan", "windows.malfind.Malfind"],
                "linux": ["linux.pslist.PsList", "linux.pstree.PsTree",
                          "linux.psaux.PsAux", "linux.sockstat.Sockstat",
                          "linux.bash.Bash", "linux.malfind.Malfind"],
                "mac": ["mac.pslist.PsList", "mac.pstree.PsTree", "mac.psaux.Psaux",
                        "mac.netstat.Netstat", "mac.malfind.Malfind"],
            },
            "vol2": {
                "windows": ["pslist", "pstree", "cmdline", "netscan", "malfind",
                            "psxview"],
                "linux": ["linux_pslist", "linux_pstree", "linux_psaux",
                          "linux_netstat", "linux_bash", "linux_malfind"],
                "mac": ["mac_pslist", "mac_pstree", "mac_psaux", "mac_netstat",
                        "mac_malfind"],
            },
        },
    },
    "processes": {
        "key": "processes",
        "label": "Process Deep Dive",
        "icon": "layout",
        "blurb": "Every process view there is, plus DLLs, handles, SIDs and privileges.",
        "plugins": {
            "vol3": {
                "windows": ["windows.pslist.PsList", "windows.psscan.PsScan",
                            "windows.pstree.PsTree", "windows.cmdline.CmdLine",
                            "windows.dlllist.DllList", "windows.handles.Handles",
                            "windows.getsids.GetSIDs", "windows.privileges.Privs",
                            "windows.envars.Envars", "windows.sessions.Sessions"],
                "linux": ["linux.pslist.PsList", "linux.psscan.PsScan",
                          "linux.pstree.PsTree", "linux.psaux.PsAux",
                          "linux.lsof.Lsof", "linux.envars.Envars",
                          "linux.library_list.LibraryList"],
                "mac": ["mac.pslist.PsList", "mac.pstree.PsTree", "mac.psaux.Psaux",
                        "mac.lsof.Lsof"],
            },
            "vol2": {
                "windows": ["pslist", "psscan", "pstree", "psxview", "cmdline",
                            "dlllist", "handles", "getsids", "privs", "envars"],
                "linux": ["linux_pslist", "linux_pstree", "linux_psaux",
                          "linux_lsof", "linux_library_list", "linux_psxview",
                          "linux_pidhashtable"],
                "mac": ["mac_pslist", "mac_pstree", "mac_psaux", "mac_lsof"],
            },
        },
    },
    "network": {
        "key": "network",
        "label": "Network Activity",
        "icon": "exchange",
        "blurb": "Connections, listeners and sockets — live and reclaimed.",
        "plugins": {
            "vol3": {
                "windows": ["windows.netscan.NetScan", "windows.netstat.NetStat",
                            "windows.cmdline.CmdLine"],
                "linux": ["linux.sockstat.Sockstat", "linux.ip.Addr", "linux.ip.Link",
                          "linux.lsof.Lsof"],
                "mac": ["mac.netstat.Netstat", "mac.ifconfig.Ifconfig"],
            },
            "vol2": {
                "windows": ["netscan", "connections", "connscan", "sockets",
                            "sockscan", "cmdline"],
                "linux": ["linux_netstat", "linux_ifconfig", "linux_arp",
                          "linux_route_cache"],
                "mac": ["mac_netstat", "mac_ifconfig"],
            },
        },
    },
    "malware_hunt": {
        "key": "malware_hunt",
        "label": "Malware Hunt",
        "icon": "bug",
        "blurb": "Injection, hollowing, hooks, unlinked modules and rootkit checks.",
        "plugins": {
            "vol3": {
                "windows": ["windows.malfind.Malfind", "windows.ldrmodules.LdrModules",
                            "windows.psxview.PsXView", "windows.psscan.PsScan",
                            "windows.suspicious_threads.SuspiciousThreads",
                            "windows.hollowprocesses.HollowProcesses",
                            "windows.processghosting.ProcessGhosting",
                            "windows.unhooked_system_calls.unhooked_system_calls",
                            "windows.etwpatch.EtwPatch",
                            "windows.ssdt.SSDT", "windows.callbacks.Callbacks",
                            "windows.modscan.ModScan", "windows.drivermodule.DriverModule",
                            "windows.driverirp.DriverIrp",
                            "windows.mutantscan.MutantScan", "windows.svcscan.SvcScan"],
                "linux": ["linux.malfind.Malfind", "linux.check_syscall.Check_syscall",
                          "linux.check_modules.Check_modules",
                          "linux.hidden_modules.Hidden_modules",
                          "linux.malware.modxview.Modxview",
                          "linux.malware.process_spoofing.ProcessSpoofing",
                          "linux.tracing.ftrace.CheckFtrace", "linux.netfilter.Netfilter",
                          "linux.check_afinfo.Check_afinfo", "linux.tty_check.tty_check",
                          "linux.keyboard_notifiers.Keyboard_notifiers"],
                "mac": ["mac.malfind.Malfind", "mac.check_syscall.Check_syscall",
                        "mac.lsmod.Lsmod"],
            },
            "vol2": {
                "windows": ["malfind", "ldrmodules", "apihooks", "psxview", "ssdt",
                            "callbacks", "modscan", "driverirp", "mutantscan",
                            "svcscan", "unloadedmodules"],
                "linux": ["linux_malfind", "linux_check_syscall", "linux_check_modules",
                          "linux_hidden_modules", "linux_check_afinfo",
                          "linux_check_tty", "linux_keyboard_notifiers", "linux_psxview"],
                "mac": ["mac_malfind", "mac_check_syscall", "mac_lsmod", "mac_psxview"],
            },
        },
    },
    "persistence": {
        "key": "persistence",
        "label": "Persistence & Execution",
        "icon": "anchor",
        "blurb": "Services, tasks, Run keys, shimcache, userassist — how it survives reboot.",
        "plugins": {
            "vol3": {
                "windows": ["windows.svcscan.SvcScan", "windows.scheduled_tasks.ScheduledTasks",
                            "windows.registry.hivelist.HiveList",
                            "windows.registry.userassist.UserAssist",
                            "windows.shimcachemem.ShimcacheMem",
                            "windows.registry.amcache.Amcache",
                            "windows.svcdiff.SvcDiff",
                            "windows.modules.Modules"],
                "linux": ["linux.lsmod.Lsmod", "linux.check_modules.Check_modules",
                          "linux.bash.Bash", "linux.mountinfo.MountInfo"],
                "mac": ["mac.lsmod.Lsmod", "mac.bash.Bash"],
            },
            "vol2": {
                "windows": ["svcscan", "servicediff", "hivelist", "userassist",
                            "shimcache", "amcache", "shellbags", "modules"],
                "linux": ["linux_lsmod", "linux_check_modules", "linux_bash",
                          "linux_mount"],
                "mac": ["mac_lsmod", "mac_bash"],
            },
        },
    },
    "credentials": {
        "key": "credentials",
        "label": "Credentials",
        "icon": "key",
        "blurb": "Hashes, LSA secrets, cached domain creds and clipboard leftovers.",
        "plugins": {
            "vol3": {
                "windows": ["windows.hashdump.Hashdump", "windows.lsadump.Lsadump",
                            "windows.cachedump.Cachedump",
                            "windows.skeleton_key_check.Skeleton_Key_Check"],
                "linux": ["linux.bash.Bash", "linux.envars.Envars",
                          "linux.check_creds.Check_creds"],
                "mac": ["mac.bash.Bash"],
            },
            "vol2": {
                "windows": ["hashdump", "lsadump", "cachedump", "clipboard",
                            "truecryptmaster"],
                "linux": ["linux_bash", "linux_bash_env", "linux_check_creds"],
                "mac": ["mac_bash"],
            },
        },
    },
    "timeline": {
        "key": "timeline",
        "label": "Timeline & History",
        "icon": "clock",
        "blurb": "Everything with a timestamp: MFT, console history, event logs, browser cache.",
        "plugins": {
            "vol3": {
                "windows": ["timeliner.Timeliner", "windows.mftscan.MFTScan",
                            "windows.cmdscan.CmdScan", "windows.consoles.Consoles",
                            "windows.registry.userassist.UserAssist",
                            "windows.shimcachemem.ShimcacheMem"],
                "linux": ["linux.bash.Bash", "linux.kmsg.Kmsg", "linux.boottime.Boottime"],
                "mac": ["mac.bash.Bash"],
            },
            "vol2": {
                "windows": ["timeliner", "mftparser", "cmdscan", "consoles",
                            "evtlogs", "iehistory", "userassist", "shimcache"],
                "linux": ["linux_bash", "linux_dmesg"],
                "mac": ["mac_bash"],
            },
        },
    },
    "files": {
        "key": "files",
        "label": "Files & Artefacts",
        "icon": "file",
        "blurb": "File objects, MFT records, cached content and loose artefacts.",
        "plugins": {
            "vol3": {
                "windows": ["windows.filescan.FileScan", "windows.mftscan.MFTScan",
                            "windows.mftscan.ADS", "windows.mbrscan.MBRScan"],
                "linux": ["linux.pagecache.Files", "linux.lsof.Lsof",
                          "linux.mountinfo.MountInfo"],
                "mac": ["mac.lsof.Lsof"],
            },
            "vol2": {
                "windows": ["filescan", "mftparser", "mbrparser", "notepad",
                            "clipboard"],
                "linux": ["linux_enumerate_files", "linux_dentry_cache", "linux_lsof"],
                "mac": ["mac_lsof"],
            },
        },
    },
    "full": {
        "key": "full",
        "label": "Full Analysis",
        "icon": "target",
        "blurb": "Every non-destructive plugin for the detected OS. Slow — run it and go make coffee.",
        "full": True,
        "plugins": {},
    },
}

# Plugins excluded from "Full Analysis": they need mandatory arguments, write
# huge amounts of data, or take hours on their own.
FULL_EXCLUDE = {
    "vol3": {
        "windows.registry.printkey.PrintKey", "windows.memmap.Memmap",
        "windows.dumpfiles.DumpFiles", "windows.strings.Strings",
        "windows.pedump.PEDump", "yarascan.YaraScan",
        "windows.vadyarascan.VadYaraScan", "linux.vmayarascan.VmaYaraScan",
        "regexscan.RegExScan", "layerwriter.LayerWriter",
        "windows.poolscanner.PoolScanner", "windows.handles.Handles",
        "windows.vadinfo.VadInfo", "windows.vadwalk.VadWalk",
        "linux.pagecache.InodePages", "configwriter.ConfigWriter",
        "windows.iat.IAT", "windows.threads.Threads",
    },
    "vol2": {
        "printkey", "memdump", "memmap", "procdump", "dumpfiles", "dlldump",
        "moddump", "vaddump", "yarascan", "linux_yarascan", "hivedump",
        "dumpregistry", "screenshot", "linux_find_file", "impscan",
        "truecryptpassphrase", "linux_enumerate_files", "handles", "vadinfo",
        "vadwalk", "vadtree", "linux_pslist_cache", "mac_dump_file", "enumfunc",
    },
}


def merge_discovered(engine: str, discovered: List[dict]) -> Dict[str, dict]:
    """Overlay whatever the runner reports on top of the curated catalog."""
    merged: Dict[str, dict] = {k: dict(v) for k, v in CATALOG.get(engine, {}).items()}
    seen = set()
    for item in discovered or []:
        name = item.get("name")
        if not name:
            continue
        seen.add(name)
        if name in merged:
            merged[name]["available"] = True
            if item.get("requirements"):
                merged[name]["requirements"] = item["requirements"]
        else:
            os_name = (item.get("os") or "").lower()
            if os_name not in ("windows", "linux", "mac"):
                os_name = "generic"
            merged[name] = {
                "name": name,
                "label": name.split(".")[-1] if "." in name else name,
                "category": "Other",
                "os": os_name,
                "family": "other",
                "popular": False,
                "description": item.get("description", ""),
                "engine": engine,
                "curated": False,
                "available": True,
                "args": ARG_SPECS.get(name, []),
                "requirements": item.get("requirements", []),
            }
    if seen:
        for name, meta in merged.items():
            meta.setdefault("available", name in seen)
    else:
        # Runner unreachable — assume the curated list is what we have.
        for meta in merged.values():
            meta.setdefault("available", True)
    return merged


def preset_plugins(preset_key: str, engine: str, os_name: str,
                   available: Dict[str, dict]) -> List[str]:
    preset = PRESETS.get(preset_key)
    if not preset:
        return []
    os_name = (os_name or "windows").lower()
    if preset.get("full"):
        out = []
        for name, meta in available.items():
            if not meta.get("available", True):
                continue
            if name in FULL_EXCLUDE.get(engine, set()):
                continue
            if meta["os"] not in (os_name, "generic"):
                continue
            if meta.get("args") and any(a.get("required") for a in meta["args"]):
                continue
            out.append(name)
        return sorted(out)
    wanted = preset["plugins"].get(engine, {}).get(os_name, [])
    return [p for p in wanted if available.get(p, {}).get("available", True)]


def family_of(engine: str, plugin: str) -> str:
    meta = CATALOG.get(engine, {}).get(plugin)
    if meta:
        return meta["family"]
    return "other"


def meta_of(engine: str, plugin: str) -> dict:
    return CATALOG.get(engine, {}).get(plugin, {
        "name": plugin, "label": plugin, "category": "Other", "os": "generic",
        "family": "other", "popular": False, "description": "", "engine": engine,
        "args": [],
    })


def popular(engine: str, os_name: str = "windows") -> List[dict]:
    out = [m for m in CATALOG.get(engine, {}).values()
           if m["popular"] and m["os"] in (os_name, "generic")]
    return sorted(out, key=lambda m: (CATEGORY_ORDER.index(m["category"])
                                      if m["category"] in CATEGORY_ORDER else 99,
                                      m["label"]))


def grouped(available: Dict[str, dict], os_filter: str = "") -> List[dict]:
    """Group plugins by category for the picker UI."""
    buckets: Dict[str, List[dict]] = {}
    for meta in available.values():
        if os_filter and meta["os"] not in (os_filter, "generic"):
            continue
        buckets.setdefault(meta["category"], []).append(meta)
    out = []
    for cat in CATEGORY_ORDER:
        if cat in buckets:
            out.append({
                "category": cat,
                "icon": CATEGORY_ICONS.get(cat, "dot"),
                "plugins": sorted(buckets[cat], key=lambda m: (not m["popular"], m["label"])),
            })
    for cat in sorted(set(buckets) - set(CATEGORY_ORDER)):
        out.append({"category": cat, "icon": "dot",
                    "plugins": sorted(buckets[cat], key=lambda m: m["label"])})
    return out

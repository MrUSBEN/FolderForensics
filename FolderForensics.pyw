#!/usr/bin/env python3
"""
Folder Forensics - find abandoned folders by reading evidence from the system itself.

Point it at ANY folder (AppData\\Local, LocalLow, Roaming, Program Files, ProgramData, D:\\Games...).
Each immediate subfolder is classified into:
  * Probably orphaned - evidence the owning program is gone (or folder is empty / very stale)
  * Unknown           - no evidence either way; you decide
  * In use            - matches an installed/running program, registered install path, etc.
Nothing is deleted automatically. You multi-select per bucket, then choose
Recycle Bin (reversible) or permanent delete.

Windows only. Python 3.8+. No third-party packages.
"""
import os, re, sys, stat, time, shutil, struct, codecs, ctypes, queue, difflib, datetime, threading, json, subprocess
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import winreg
except ImportError:
    winreg = None

# ----------------------------------------------------------------------------- helpers
NOISE = {"inc", "llc", "ltd", "gmbh", "corp", "corporation", "co", "company", "studio", "studios",
         "software", "entertainment", "technologies", "technology", "interactive", "the", "team",
         "publishing", "limited", "softworks", "labs", "games", "game"}
GENERIC = {"bin", "x64", "x86", "win64", "win32", "binaries", "programfiles", "programfilesx86",
           "programs", "app", "application", "release", "windows", "system32", "users", "common",
           "steamapps", "steam", "data", "program", "files", "local", "appdata", "roaming", "temp",
           "launcher", "setup", "install", "installer", "update", "updater", "games", "game",
           "steamlibrary", "downloads", "desktop", "documents", "microsoft", "shipping", "client"}
PROTECTED = {"microsoft", "packages", "temp", "d3dscache", "connecteddevicesplatform", "publishers",
             "virtualstore", "tempstate", "programs", "history", "windows", "system32", "program files",
             "program files (x86)", "programdata", "users", "$recycle.bin", "system volume information",
             "recovery", "boot", "windowsapps", "appdata", "comms", "packages"}
SAVE_EXT = {".sav", ".save", ".sl2", ".dat", ".slot", ".savegame"}
SAVE_DIRS = {"saves", "save", "savegames", "savedgames", "profiles", "profile"}
TEXT_EXT = {".json", ".ini", ".cfg", ".conf", ".xml", ".log", ".txt", ".config", ".yaml", ".yml", ".toml"}
STALE_DAYS = 730


def norm(s):
    words = re.findall(r"[a-z0-9]+", (s or "").lower())
    kept = [w for w in words if w not in NOISE]
    return "".join(kept or words)


def nc(p):
    return os.path.normcase(os.path.normpath(p))


def under(a, b):
    """True if path a equals or is inside path b (both normalised with nc)."""
    return a == b or a.startswith(b.rstrip("\\") + "\\")


def depth(p):
    return len([x for x in os.path.splitdrive(p)[1].split("\\") if x])


def state(path):
    drive = os.path.splitdrive(path)[0]
    if drive and not os.path.exists(drive + "\\"):
        return "offline"
    return "live" if os.path.exists(path) else "ghost"


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def rv(key, name):
    try:
        v = winreg.QueryValueEx(key, name)[0]
        return v if isinstance(v, str) else ""
    except OSError:
        return ""


EXE_RE = re.compile(r'[A-Za-z]:\\[^"*?<>|]*?\.exe', re.I)

# ----------------------------------------------------------------------------- exe version info
def version_strings(path):
    try:
        ver = ctypes.windll.version
        ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
        ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return {}
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return {}
        lp, ln = ctypes.c_void_p(), ctypes.c_uint()
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(lp), ctypes.byref(ln)) or ln.value < 4:
            return {}
        lang, cp = struct.unpack("<HH", ctypes.string_at(lp.value, 4))
        out = {}
        for k in ("CompanyName", "ProductName"):
            if ver.VerQueryValueW(buf, f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{k}", ctypes.byref(lp), ctypes.byref(ln)) and ln.value:
                out[k] = ctypes.wstring_at(lp.value)
        return out
    except Exception:
        return {}

# ----------------------------------------------------------------------------- evidence index
def build_index(log):
    EV, LOCS = [], []   # EV: (kind, norm, live, src, desc)   LOCS: (path, live, desc)

    def add_ev(kind, text, live, src, desc):
        n = norm(text)
        if len(n) < 3 or n in GENERIC or n.startswith("unins"):
            return
        EV.append((kind, n, live, src or "", desc))

    def add_loc(path, live, desc):
        p = nc(path)
        if depth(p) >= 2:
            LOCS.append((p, live, desc))

    def path_evidence(kind, path, desc):
        path = path.strip().strip('"')
        st = state(path)
        live = st != "ghost"
        note = " (drive offline)" if st == "offline" else ("" if live else " (no longer exists)")
        stem = re.sub(r"-win(64|32)-shipping$", "", Path(path).stem, flags=re.I)
        d = f"{desc}: {path}{note}"
        add_ev(kind, stem, live, path, d)
        for part in [x for x in re.split(r"[\\/]", os.path.dirname(path)) if x][-2:]:
            add_ev(kind, part, live, path, d)

    # 1. Uninstall registry
    log("Reading installed programs (registry)...")
    HKLM, HKCU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for hive, sub in [(HKLM, base), (HKLM, base.replace("SOFTWARE", r"SOFTWARE\WOW6432Node")),
                      (HKCU, base)]:
        try:
            k = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(k)[0]):
            try:
                with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                    name, pub = rv(sk, "DisplayName"), rv(sk, "Publisher")
                    loc = rv(sk, "InstallLocation").strip().strip('"').rstrip("\\")
                    if not loc:
                        m = EXE_RE.search(rv(sk, "DisplayIcon") or rv(sk, "UninstallString"))
                        if m and "windows" not in m.group(0).lower():
                            loc = os.path.dirname(m.group(0))
            except OSError:
                continue
            live, d = True, f"Installed program '{name or pub}'"
            if loc:
                st = state(loc)
                live = st != "ghost"
                d += f" at {loc}" + (" (drive offline)" if st == "offline" else "" if live else " (folder missing - stale uninstall entry)")
                add_loc(loc, live, d)
                add_ev("uninstall", os.path.basename(loc), live, loc, d)
            add_ev("uninstall", name, live, loc, d)
            add_ev("publisher", pub, live, loc, d)

    # 2. Steam
    log("Reading Steam / Epic / GOG libraries...")
    steam = ""
    for hive, sub, val in [(HKCU, r"Software\Valve\Steam", "SteamPath"),
                           (HKLM, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath")]:
        try:
            with winreg.OpenKey(hive, sub) as sk:
                steam = rv(sk, val)
                if steam:
                    break
        except OSError:
            pass
    if steam:
        libs = {os.path.normpath(steam)}
        try:
            txt = open(os.path.join(steam, "steamapps", "libraryfolders.vdf"), encoding="utf-8", errors="ignore").read()
            libs |= {os.path.normpath(p.replace("\\\\", "\\")) for p in re.findall(r'"path"\s+"([^"]+)"', txt)}
        except OSError:
            pass
        for lib in libs:
            apps = os.path.join(lib, "steamapps")
            try:
                acfs = [f for f in os.listdir(apps) if f.startswith("appmanifest_")]
            except OSError:
                continue
            for f in acfs:
                try:
                    t = open(os.path.join(apps, f), encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                nm = re.search(r'"name"\s+"([^"]*)"', t)
                inst = re.search(r'"installdir"\s+"([^"]*)"', t)
                folder = os.path.join(apps, "common", inst.group(1)) if inst else ""
                live = os.path.exists(folder) if folder else True
                d = f"Steam game '{nm.group(1) if nm else f}'" + ("" if live else " (manifest left behind, files gone)")
                if folder:
                    add_loc(folder, live, d)
                    add_ev("steam", inst.group(1), live, folder, d)
                if nm:
                    add_ev("steam", nm.group(1), live, folder, d)

    # 3. Epic
    epic = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Epic", "EpicGamesLauncher", "Data", "Manifests")
    if os.path.isdir(epic):
        for f in os.listdir(epic):
            if f.endswith(".item"):
                try:
                    j = json.load(open(os.path.join(epic, f), encoding="utf-8", errors="ignore"))
                except Exception:
                    continue
                loc = j.get("InstallLocation", "")
                live = os.path.exists(loc) if loc else True
                d = f"Epic game '{j.get('DisplayName', '')}'" + ("" if live else " (files gone)")
                if loc:
                    add_loc(loc, live, d)
                    add_ev("epic", os.path.basename(loc), live, loc, d)
                add_ev("epic", j.get("DisplayName", ""), live, loc, d)

    # 4. GOG
    try:
        with winreg.OpenKey(HKLM, r"SOFTWARE\WOW6432Node\GOG.com\Games") as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                    loc, nm = rv(sk, "path"), rv(sk, "gameName")
                    live = os.path.exists(loc) if loc else True
                    d = f"GOG game '{nm}'"
                    if loc:
                        add_loc(loc, live, d)
                    add_ev("gog", nm, live, loc, d)
    except OSError:
        pass

    # 5. Startup entries + App Paths
    log("Reading startup entries and App Paths...")
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    for hive, sub in [(HKCU, run), (HKLM, run), (HKLM, run.replace("Software", r"Software\WOW6432Node"))]:
        try:
            with winreg.OpenKey(hive, sub) as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    _, val, _ = winreg.EnumValue(k, i)
                    m = EXE_RE.search(str(val))
                    if m:
                        path_evidence("startup", m.group(0), "Startup entry")
        except OSError:
            pass
    try:
        ap = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        with winreg.OpenKey(HKLM, ap) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                    m = EXE_RE.search(rv(sk, ""))
                    if m:
                        path_evidence("apppath", m.group(0), "App Paths entry")
    except OSError:
        pass

    # 6. UserAssist: programs that once ran (gives GHOST evidence for deleted programs)
    log("Reading run history (UserAssist)...")
    known = {"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": os.environ.get("ProgramFiles", r"C:\Program Files"),
             "{6D809377-6AF0-444B-8957-A3773F02200E}": os.environ.get("ProgramW6432", r"C:\Program Files"),
             "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")}
    try:
        ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        with winreg.OpenKey(HKCU, ua) as k:
            for gi in range(winreg.QueryInfoKey(k)[0]):
                try:
                    ck = winreg.OpenKey(k, winreg.EnumKey(k, gi) + r"\Count")
                except OSError:
                    continue
                for vi in range(winreg.QueryInfoKey(ck)[1]):
                    nm, data, _ = winreg.EnumValue(ck, vi)
                    p = codecs.decode(nm, "rot13")
                    for g, real in known.items():
                        if p.upper().startswith(g):
                            p = real + p[len(g):]
                    if not (re.match(r"[A-Za-z]:\\", p) and p.lower().endswith(".exe")):
                        continue
                    when = ""
                    if isinstance(data, bytes) and len(data) >= 68:
                        ft = struct.unpack_from("<Q", data, 60)[0]
                        if ft:
                            try:
                                when = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)).strftime("%Y-%m-%d")
                            except OverflowError:
                                pass
                    path_evidence("history", p, f"Ran before (last {when or '?'})")
    except OSError:
        pass

    # 7. Executable metadata from installed apps (vendor / product names, Unity app.info)
    log("Scanning installed app folders for executable metadata...")
    pf = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
          os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")]
    app_dirs = {}
    for root in filter(None, pf):
        try:
            for e in os.scandir(root):
                if e.is_dir():
                    app_dirs[nc(e.path)] = e.path
        except OSError:
            pass
    for lp, live, _ in LOCS:
        if live and os.path.isdir(lp):
            app_dirs.setdefault(lp, lp)
    for d in list(app_dirs.values()):
        add_ev("appdir", os.path.basename(d), True, d, f"Installed app folder: {d}")
        exes, base = 0, d.count(os.sep)
        for dp, dn, fn in os.walk(d):
            if dp.count(os.sep) - base >= 3:
                dn[:] = []
            if dp.lower().endswith("_data"):
                ai = os.path.join(dp, "app.info")
                if os.path.isfile(ai):
                    try:
                        lines = open(ai, encoding="utf-8", errors="ignore").read().splitlines()
                        for ln in lines[:2]:
                            add_ev("unity", ln, True, ai, f"Unity game info: {ai}")
                    except OSError:
                        pass
            for f in fn:
                if f.lower().endswith(".exe") and exes < 6:
                    exes += 1
                    full = os.path.join(dp, f)
                    stem = re.sub(r"-win(64|32)-shipping$", "", Path(f).stem, flags=re.I)
                    add_ev("exe", stem, True, full, f"Executable: {full}")
                    vs = version_strings(full)
                    for key in ("CompanyName", "ProductName"):
                        if vs.get(key):
                            add_ev("exe", vs[key], True, full, f"{key} in {full}")

    # 8. Windows services (registry - no admin needed to read ImagePath)
    log("Reading Windows services...")
    try:
        with winreg.OpenKey(HKLM, r"SYSTEM\CurrentControlSet\Services") as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                try:
                    name = winreg.EnumKey(k, i)
                    with winreg.OpenKey(k, name) as sk:
                        img = rv(sk, "ImagePath")
                except OSError:
                    continue
                m = EXE_RE.search(img) if img else None
                if m:
                    path_evidence("service", m.group(0), f"Windows service '{name}'")
    except OSError:
        log("Services registry key not accessible - skipping.")

    # 9. Scheduled tasks (XML files Task Scheduler stores on disk)
    log("Reading scheduled tasks...")
    tasks_root = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "Tasks")
    cmd_re = re.compile(r"<Command>(.*?)</Command>", re.I | re.S)
    wd_re = re.compile(r"<WorkingDirectory>(.*?)</WorkingDirectory>", re.I | re.S)
    count, stop = 0, False
    for dp, dn, fn in os.walk(tasks_root):
        if stop:
            break
        for f in fn:
            count += 1
            if count > 3000:
                stop = True
                break
            fp = os.path.join(dp, f)
            try:
                raw = open(fp, "rb").read(16384)
            except OSError:
                continue
            text = raw.decode("utf-16", "ignore") if raw[:2] == b"\xff\xfe" else raw.decode("utf-8", "ignore")
            for rex, label in ((cmd_re, "Command"), (wd_re, "Working dir")):
                m = rex.search(text)
                if m:
                    val = os.path.expandvars(m.group(1).strip())
                    if re.match(r"[A-Za-z]:\\", val):
                        path_evidence("task", val, f"Scheduled task '{f}' ({label})")

    # 10. Start Menu shortcuts + installed Windows Store (UWP/Appx) apps, via one PowerShell call.
    # This is local system introspection only - no network access, nothing leaves the machine.
    log("Reading Start Menu shortcuts and Windows Store apps...")
    sm_paths = [p for p in [
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
    ] if p and os.path.isdir(p)]
    data = {}
    if sm_paths:
        ps_paths = ",".join("'" + p.replace("'", "''") + "'" for p in sm_paths)
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$shell = New-Object -ComObject WScript.Shell;"
            f"$links = Get-ChildItem -Path {ps_paths} -Filter *.lnk -Recurse -ErrorAction SilentlyContinue;"
            "$out = @();"
            "foreach ($l in $links) { try { $sc = $shell.CreateShortcut($l.FullName); "
            "$out += [PSCustomObject]@{ Name=$l.BaseName; Target=$sc.TargetPath } } catch {} };"
            "$apps = @(Get-AppxPackage -ErrorAction SilentlyContinue | "
            "Select-Object Name, PackageFamilyName, InstallLocation);"
            "[PSCustomObject]@{ Shortcuts = @($out); Apps = $apps } | ConvertTo-Json -Depth 4 -Compress"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.stdout.strip():
                data = json.loads(r.stdout)
        except Exception as ex:
            log(f"Start Menu / Store apps scan unavailable ({ex}) - skipping.")
    for sc in (data.get("Shortcuts") or []):
        tgt, nm = (sc or {}).get("Target") or "", (sc or {}).get("Name") or ""
        if re.match(r"[A-Za-z]:\\", tgt):
            path_evidence("shortcut", tgt, f"Start Menu shortcut '{nm}'")
    for ap in (data.get("Apps") or []):
        fam, loc, nm = (ap or {}).get("PackageFamilyName") or "", (ap or {}).get("InstallLocation") or "", (ap or {}).get("Name") or ""
        live = os.path.exists(loc) if loc else True
        d = f"Windows Store app '{nm or fam}'"
        if fam:
            add_ev("appx", fam, live, loc, d)
        if nm:
            add_ev("appx", nm, live, loc, d)
        if loc:
            add_loc(loc, live, d)

    # 11. Currently running processes (proves "in use" beyond any doubt; also catches portable
    # apps with no registry/Start Menu presence at all). Best effort - some processes are
    # protected and simply get skipped.
    log("Reading currently running processes...")
    try:
        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                        ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                        ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260)]
        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                     ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        pids = []
        if snap:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if k32.Process32FirstW(snap, ctypes.byref(entry)):
                while True:
                    pids.append(entry.th32ProcessID)
                    if not k32.Process32NextW(snap, ctypes.byref(entry)):
                        break
            k32.CloseHandle(snap)
        seen = set()
        for pid in pids:
            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                continue
            buf, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) and buf.value not in seen:
                seen.add(buf.value)
                path_evidence("process", buf.value, "Currently running process")
            k32.CloseHandle(h)
    except Exception as ex:
        log(f"Process scan unavailable ({ex}) - skipping.")

    # 12. BAM (Background Activity Moderator) - per-exe last-run timestamps that often outlive
    # UserAssist entries. Registry key normally needs admin rights; skipped silently otherwise.
    log("Reading run history (BAM, admin only, best effort)...")
    try:
        dev_map, buf = {}, ctypes.create_unicode_buffer(260)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 260):
                dev_map[buf.value.upper()] = f"{letter}:"

        def resolve_device_path(p):
            pu = p.upper()
            for dev, drive in dev_map.items():
                if pu.startswith(dev):
                    return drive + p[len(dev):]
            return p

        with winreg.OpenKey(HKLM, r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings") as uk:
            sids = [winreg.EnumKey(uk, i) for i in range(winreg.QueryInfoKey(uk)[0])]
        for sid in sids:
            try:
                with winreg.OpenKey(HKLM, rf"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{sid}") as sk:
                    for vi in range(winreg.QueryInfoKey(sk)[1]):
                        name, val, _ = winreg.EnumValue(sk, vi)
                        if not name.lower().endswith(".exe") or not isinstance(val, bytes) or len(val) < 8:
                            continue
                        p = resolve_device_path(name)
                        if not re.match(r"[A-Za-z]:\\", p):
                            continue
                        ft, when = struct.unpack_from("<Q", val, 0)[0], ""
                        if ft:
                            try:
                                when = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)).strftime("%Y-%m-%d")
                            except OverflowError:
                                pass
                        path_evidence("bam", p, f"Ran before, BAM record (last {when or '?'})")
            except OSError:
                continue
    except OSError:
        log("BAM registry not accessible (needs admin) - skipping this evidence source.")

    exact = {}
    for i, e in enumerate(EV):
        exact.setdefault(e[1], []).append(i)
    log(f"Indexed {len(EV)} evidence entries.")
    return EV, LOCS, exact, list(exact)

# ----------------------------------------------------------------------------- inspection & classification
REF_RE = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\t]+\\)*[^\\/:*?"<>|\r\n\t]*')


def inspect(path):
    size = files = 0
    newest = 0
    saves = False
    texts = []
    try:
        newest = os.lstat(path).st_mtime
    except OSError:
        pass
    for dp, dn, fn in os.walk(path, onerror=lambda e: None):
        if os.path.basename(dp).lower() in SAVE_DIRS:
            saves = True
        for f in fn:
            fp = os.path.join(dp, f)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            size += st.st_size
            files += 1
            newest = max(newest, st.st_mtime)
            ext = os.path.splitext(f)[1].lower()
            if ext in SAVE_EXT:
                saves = True
            if ext in TEXT_EXT and st.st_size < 262144 and len(texts) < 25:
                texts.append(fp)
    return size, files, newest, saves, texts


def find_refs(files):
    refs = set()
    for f in files:
        try:
            raw = open(f, "rb").read(65536)
        except OSError:
            continue
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = raw.decode("utf-16", "ignore")
        elif b"\x00" in raw[:100]:
            text = raw.decode("utf-16-le", "ignore")
        else:
            text = raw.decode("utf-8", "ignore")
        for m in REF_RE.findall(text.replace("\\\\", "\\")):
            p = m.strip().rstrip(" .,;)'\"")
            if len(p) >= 6:
                refs.add(p)
        if len(refs) > 80:
            break
    return refs


def match_name(name, parent_path, idx):
    """Return (best_live, best_ghost) as (score, evidence) tuples."""
    EV, _, exact, norms = idx
    n = norm(name)
    if len(n) < 3:
        return None, None
    scores = {}
    for i in exact.get(n, []):
        scores[i] = 1.0
    if len(n) >= 4:
        for en in norms:
            if en == n or len(en) < 4:
                continue
            if en in n or n in en:
                sc = 0.85 if min(len(en), len(n)) / max(len(en), len(n)) >= 0.5 else 0.7
                for i in exact[en]:
                    scores[i] = max(scores.get(i, 0), sc)
        for en in difflib.get_close_matches(n, norms, n=5, cutoff=0.88):
            r = difflib.SequenceMatcher(None, n, en).ratio()
            for i in exact[en]:
                scores[i] = max(scores.get(i, 0), r)
    live = ghost = None
    for i, sc in scores.items():
        kind, _, is_live, src, _d = EV[i]
        if kind in ("exe", "unity", "appdir") and src and under(nc(src), parent_path):
            continue  # evidence coming from inside the folder itself proves nothing
        if is_live and (live is None or sc > live[0]):
            live = (sc, EV[i])
        elif not is_live and (ghost is None or sc > ghost[0]):
            ghost = (sc, EV[i])
    return live, ghost


def classify(path, idx, ignore_roots):
    EV, LOCS, _, _ = idx
    name = os.path.basename(path)
    p = nc(path)
    size, files, newest, saves, texts = inspect(path)
    age = (time.time() - newest) / 86400 if newest else 0
    reasons, flags = [], []
    if saves:
        flags.append("may hold saves")
    if files == 0:
        flags.append("empty")

    loc_live = [d for lp, l, d in LOCS if l and (under(lp, p) or under(p, lp))]
    loc_ghost = [d for lp, l, d in LOCS if not l and (under(lp, p) or under(p, lp))]
    live, ghost = match_name(name, p, idx)

    child_live = []
    if not (live and live[0] >= 0.8) and not loc_live:
        try:
            subs = [e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)][:40]
        except OSError:
            subs = []
        for s in subs:
            cl, _ = match_name(s, p, idx)
            if cl and cl[0] >= 0.85:
                child_live.append(f"subfolder '{s}' ~ {cl[1][4]}")

    refs_exist, refs_missing = [], []
    for r in find_refs(texts):
        rn = nc(r)
        if under(rn, p) or any(under(rn, ig) for ig in ignore_roots) or depth(rn) < 1:
            continue
        st = state(r)
        (refs_exist if st == "live" else refs_missing if st == "ghost" else []).append(r)

    if name.lower() in PROTECTED:
        bucket, score = "in_use", 1.0
        reasons.append("Protected system/shared folder name")
    elif loc_live:
        bucket, score = "in_use", 1.0
        reasons.append("Registered install location: " + loc_live[0])
    elif live and live[0] >= 0.8:
        bucket, score = "in_use", live[0]
        reasons.append(f"Name matches ({live[0]:.0%}): {live[1][4]}")
    elif child_live:
        bucket, score = "in_use", 0.7
        reasons.append("Contains active " + child_live[0])
    elif ghost or loc_ghost:
        bucket = "orphan"
        reasons.append("Matches a program that is gone: " + (loc_ghost[0] if loc_ghost else ghost[1][4]))
        score = 0.9 if (age > 365 or refs_missing) else 0.7
    elif refs_missing and not refs_exist:
        bucket, score = "orphan", 0.7
        reasons.append(f"Files inside point only to missing locations, e.g. {refs_missing[0]}")
    elif files == 0:
        bucket, score = "orphan", 0.95
        reasons.append("Folder contains no files")
    elif age > STALE_DAYS:
        bucket, score = "orphan", 0.4
        reasons.append(f"No name match and untouched for {age/365:.1f} years")
    else:
        bucket, score = "unknown", 0.0
        reasons.append("No evidence either way")
    if bucket != "in_use" and live:
        reasons.append(f"Weak similarity ({live[0]:.0%}): {live[1][4]}")
    if bucket != "orphan":
        if refs_missing:
            reasons.append(f"Refers to missing path: {refs_missing[0]}")
    if refs_exist:
        reasons.append(f"Refers to existing path: {refs_exist[0]}")
    if bucket == "orphan" and age > 0:
        reasons.append(f"Last modified {age:.0f} days ago")
    if saves:
        reasons.append("Contains save-like files/folders - check before deleting")
    if bucket == "in_use":
        conf = "High" if score >= 0.95 else "Medium"
    elif bucket == "orphan":
        conf = "High" if score >= 0.9 else "Medium" if score >= 0.6 else "Low"
    else:
        conf = "-"
    return SimpleNamespace(path=path, name=name, size=size, files=files, mtime=newest, bucket=bucket,
                           score=score, conf=conf, reasons=reasons, flags=flags)

# ----------------------------------------------------------------------------- deletion
class _SH(ctypes.Structure):
    _pack_ = 1 if ctypes.sizeof(ctypes.c_void_p) == 4 else 8
    _fields_ = [("hwnd", ctypes.c_void_p), ("wFunc", ctypes.c_uint), ("pFrom", ctypes.c_wchar_p),
                ("pTo", ctypes.c_wchar_p), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", ctypes.c_int),
                ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", ctypes.c_wchar_p)]


def to_recycle_bin(path):
    op = _SH()
    op.wFunc = 3                       # FO_DELETE
    op.pFrom = os.path.normpath(path) + "\0"
    op.fFlags = 0x40 | 0x10 | 0x4 | 0x400   # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if rc != 0 or op.fAnyOperationsAborted:
        raise OSError(f"Recycle Bin operation failed (code {rc}). Path may be too long or in use.")


def delete_permanently(path):
    def fix(func, p, *_):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if os.path.islink(path):
        os.unlink(path)
    elif sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: fix(f, p))
    else:
        shutil.rmtree(path, onerror=fix)

# ----------------------------------------------------------------------------- GUI
BUCKETS = [("orphan", "Probably orphaned"), ("unknown", "Unknown"), ("in_use", "In use")]
COLORS = {"green": "#dff5df", "yellow": "#fff6cc", "orange": "#ffe0b3",
          "blue": "#dbeeff", "grey": "#e6e6e6"}
LEGEND = [("green", "High confidence orphan"), ("orange", "Medium confidence, or may hold saves - be careful"),
          ("yellow", "Low confidence orphan"), ("blue", "In use"), ("grey", "Unknown / no data")]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder Forensics")
        self.geometry("1200x740")
        self.q = queue.Queue()
        self.items, self.trees, self.sort_state = {}, {}, {}
        self.checked = set()
        self.scanning = False
        self._build()
        self.after(100, self._poll)

    def _build(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Folder(s) to scan (separate with ;)").grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar(value=os.path.join(os.environ.get("LOCALAPPDATA", ""), ""))
        ttk.Entry(top, textvariable=self.path_var).grid(row=1, column=0, sticky="ew", padx=(0, 6))
        top.columnconfigure(0, weight=1)
        ttk.Button(top, text="Browse (add)...", command=self._browse).grid(row=1, column=1, padx=2)
        ttk.Button(top, text="Local", command=lambda: self._preset(["LOCALAPPDATA"])).grid(row=1, column=2, padx=2)
        ttk.Button(top, text="LocalLow", command=lambda: self._preset(["LOCALAPPDATA\\..\\LocalLow"])).grid(row=1, column=3, padx=2)
        ttk.Button(top, text="Roaming", command=lambda: self._preset(["APPDATA"])).grid(row=1, column=4, padx=2)
        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.grid(row=1, column=5, padx=(8, 0))
        self.status = tk.StringVar(value="Choose folder(s) and press Scan.")
        ttk.Label(self, textvariable=self.status, padding=(8, 0)).pack(fill="x")
        self.prog = ttk.Progressbar(self, mode="indeterminate")
        self.prog.pack(fill="x", padx=8, pady=(0, 4))

        legend = ttk.Frame(self, padding=(8, 0, 8, 4))
        legend.pack(fill="x")
        for color, label in LEGEND:
            tk.Label(legend, text="  ", background=COLORS[color], relief="solid", borderwidth=1).pack(side="left", padx=(0, 3))
            ttk.Label(legend, text=label).pack(side="left", padx=(0, 12))

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8)
        self.tabs = {}
        for key, title in BUCKETS:
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=title)
            self.tabs[key] = frame
            bar = ttk.Frame(frame)
            bar.pack(fill="x", pady=4)
            ttk.Button(bar, text="Select all", command=lambda k=key: self._sel(k, "all")).pack(side="left", padx=2)
            ttk.Button(bar, text="Select none", command=lambda k=key: self._sel(k, "none")).pack(side="left", padx=2)
            ttk.Button(bar, text="Invert", command=lambda k=key: self._sel(k, "invert")).pack(side="left", padx=2)
            ttk.Label(bar, text="Click the checkbox to mark a folder. Double-click a row to open it in Explorer.").pack(side="left", padx=10)
            cols = ("sel", "name", "size", "modified", "conf", "flags", "evidence", "location")
            tree = ttk.Treeview(frame, columns=cols, selectmode="extended", show="headings")
            tree.column("#0", width=0, stretch=False)
            heads = {"sel": "✓", "name": "Folder", "size": "Size", "modified": "Modified", "conf": "Confidence",
                     "flags": "Flags", "evidence": "Main evidence", "location": "Location"}
            widths = {"sel": 30, "name": 200, "size": 80, "modified": 90, "conf": 85,
                      "flags": 110, "evidence": 360, "location": 220}
            for c, h in heads.items():
                anchor = "center" if c == "sel" else "w"
                tree.heading(c, text=h, command=lambda c=c, t=tree: self._sort(t, c))
                tree.column(c, width=widths[c], anchor=anchor, stretch=(c not in ("sel",)))
            for color, hexval in COLORS.items():
                tree.tag_configure(color, background=hexval)
            sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=sb.set)
            tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            tree.bind("<<TreeviewSelect>>", self._on_select)
            tree.bind("<Button-1>", self._click)
            tree.bind("<Control-a>", lambda e, k=key: (self._sel(k, "all"), "break")[1])
            tree.bind("<Double-1>", self._open)
            tree.bind("<Button-3>", self._context_menu)
            self.trees[key] = tree

        self.details = tk.Text(self, height=6, wrap="word", state="disabled")
        self.details.pack(fill="x", padx=8, pady=6)
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        self.summary = tk.StringVar(value="Nothing checked")
        ttk.Label(bottom, textvariable=self.summary).pack(side="left")
        ttk.Button(bottom, text="Delete permanently", command=lambda: self.delete(False)).pack(side="right", padx=4)
        ttk.Button(bottom, text="Delete to Recycle Bin", command=lambda: self.delete(True)).pack(side="right", padx=4)

    # -- controls
    def _preset(self, envs):
        paths = [os.path.normpath(os.path.expandvars("%" + e.split("\\")[0] + "%") + "\\" + "\\".join(e.split("\\")[1:]))
                 for e in envs]
        self.path_var.set(";".join(paths))

    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            cur = self.path_var.get().strip().rstrip(";")
            self.path_var.set((cur + ";" if cur else "") + os.path.normpath(d))

    def _color_tag(self, it):
        if it.bucket == "in_use":
            return "blue"
        if it.bucket == "unknown":
            return "grey"
        if "may hold saves" in it.flags:
            return "orange"
        if it.conf == "High":
            return "green"
        if it.conf == "Medium":
            return "orange"
        return "yellow"

    def _row_values(self, it):
        when = datetime.datetime.fromtimestamp(it.mtime).strftime("%Y-%m-%d") if it.mtime else "-"
        box = "☑" if it.path in self.checked else "☐"
        return (box, it.name, human(it.size), when, it.conf, ", ".join(it.flags), it.reasons[0], os.path.dirname(it.path))

    def _click(self, event):
        tree = event.widget
        if tree.identify_region(event.x, event.y) != "cell":
            return
        if tree.identify_column(event.x) == "#1":
            row = tree.identify_row(event.y)
            if row:
                self._toggle_check(row)

    def _toggle_check(self, path):
        if path in self.checked:
            self.checked.discard(path)
        else:
            self.checked.add(path)
        it = self.items[path]
        tree = self.trees[it.bucket]
        vals = list(tree.item(path, "values"))
        vals[0] = "☑" if path in self.checked else "☐"
        tree.item(path, values=vals)
        self._update_summary()

    def _sel(self, key, mode):
        tree = self.trees[key]
        kids = tree.get_children()
        for iid in kids:
            if mode == "all":
                self.checked.add(iid)
            elif mode == "none":
                self.checked.discard(iid)
            else:
                self.checked.symmetric_difference_update({iid})
        for iid in kids:
            vals = list(tree.item(iid, "values"))
            vals[0] = "☑" if iid in self.checked else "☐"
            tree.item(iid, values=vals)
        self._update_summary()

    def _sort(self, tree, col):
        rev = self.sort_state.get((id(tree), col), False)
        keyf = {"sel": lambda i: i.path in self.checked, "name": lambda i: i.name.lower(), "size": lambda i: i.size,
                "modified": lambda i: i.mtime, "conf": lambda i: i.score, "flags": lambda i: ",".join(i.flags),
                "evidence": lambda i: i.reasons[0], "location": lambda i: os.path.dirname(i.path).lower()}[col]
        order = sorted(tree.get_children(), key=lambda iid: keyf(self.items[iid]), reverse=not rev)
        for n, iid in enumerate(order):
            tree.move(iid, "", n)
        self.sort_state[(id(tree), col)] = not rev

    def _open(self, event):
        tree = event.widget
        row = tree.identify_row(event.y)
        if row:
            self._open_path(row)

    def _open_path(self, path):
        try:
            os.startfile(path)
        except OSError as ex:
            messagebox.showerror("Folder Forensics", f"Couldn't open folder:\n{ex}")

    def _copy_path(self, path):
        self.clipboard_clear()
        self.clipboard_append(path)

    def _context_menu(self, event):
        tree = event.widget
        row = tree.identify_row(event.y)
        if not row:
            return
        if row not in tree.selection():
            tree.selection_set(row)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Open in Explorer", command=lambda: self._open_path(row))
        menu.add_command(label="Copy full path", command=lambda: self._copy_path(row))
        menu.add_separator()
        menu.add_command(label="Uncheck" if row in self.checked else "Check",
                         command=lambda: self._toggle_check(row))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _update_summary(self):
        sel = [self.items[p] for p in self.checked if p in self.items]
        self.summary.set(f"{len(sel)} checked, {human(sum(i.size for i in sel))}" if sel else "Nothing checked")

    def _on_select(self, event=None):
        tree = event.widget if event else None
        sel = tree.selection() if tree else []
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        if len(sel) == 1:
            i = self.items[sel[0]]
            self.details.insert("end", f"{i.path}\n{human(i.size)} in {i.files} files\n\n" + "\n".join("- " + r for r in i.reasons))
        elif len(sel) > 1:
            self.details.insert("end", f"{len(sel)} rows highlighted. Tick their checkboxes to mark them for deletion.")
        self.details.config(state="disabled")

    # -- scanning
    def start_scan(self):
        if self.scanning:
            return
        roots = [os.path.normpath(p.strip()) for p in self.path_var.get().split(";") if p.strip()]
        roots = [r for r in roots if os.path.isdir(r)]
        if not roots:
            messagebox.showerror("Folder Forensics", "No valid folder to scan.")
            return
        for t in self.trees.values():
            t.delete(*t.get_children())
        self.items.clear()
        self.checked.clear()
        self._update_summary()
        self.scanning = True
        self.scan_btn.state(["disabled"])
        self.prog.start(12)
        threading.Thread(target=self._scan, args=(roots,), daemon=True).start()

    def _scan(self, roots):
        try:
            idx = build_index(lambda m: self.q.put(("status", m)))
            ignore = [nc(os.environ.get(v, "")) for v in ("LOCALAPPDATA", "APPDATA", "TEMP", "WINDIR") if os.environ.get(v)]
            cands = []
            for r in roots:
                try:
                    cands += [e.path for e in os.scandir(r) if e.is_dir(follow_symlinks=False)]
                except OSError:
                    pass
            for n, c in enumerate(cands, 1):
                self.q.put(("status", f"Analysing {n}/{len(cands)}: {os.path.basename(c)}"))
                try:
                    self.q.put(("item", classify(c, idx, ignore)))
                except Exception as ex:
                    self.q.put(("status", f"Skipped {c}: {ex}"))
            self.q.put(("done", len(cands)))
        except Exception as ex:
            self.q.put(("err", str(ex)))

    def _add_item(self, it):
        self.items[it.path] = it
        tag = self._color_tag(it)
        self.trees[it.bucket].insert("", "end", iid=it.path, values=self._row_values(it), tags=(tag,))

    def _retitle(self):
        for i, (key, title) in enumerate(BUCKETS):
            self.nb.tab(i, text=f"{title} ({len(self.trees[key].get_children())})")

    def _poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "status":
                    self.status.set(val)
                elif kind == "item":
                    self._add_item(val)
                elif kind == "done":
                    self.scanning = False
                    self.prog.stop()
                    self.scan_btn.state(["!disabled"])
                    for t in self.trees.values():
                        self._sort(t, "size")
                    self._retitle()
                    self.status.set(f"Done. {val} folders analysed.")
                elif kind == "err":
                    self.scanning = False
                    self.prog.stop()
                    self.scan_btn.state(["!disabled"])
                    messagebox.showerror("Folder Forensics", val)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # -- deleting
    def delete(self, recycle):
        sel = [self.items[p] for p in list(self.checked) if p in self.items]
        if not sel:
            messagebox.showinfo("Folder Forensics", "Nothing checked. Tick the checkboxes next to the folders you want to remove.")
            return
        total = human(sum(i.size for i in sel))
        counts = {k: sum(1 for i in sel if i.bucket == k) for k, _ in BUCKETS}
        msg = (f"{'Move to Recycle Bin' if recycle else 'PERMANENTLY DELETE'} {len(sel)} folders ({total})?\n\n"
               + "\n".join(f"  {t}: {counts[k]}" for k, t in BUCKETS if counts[k]))
        if counts["in_use"]:
            msg += f"\n\nWARNING: {counts['in_use']} of these look IN USE."
        saves = sum(1 for i in sel if "may hold saves" in i.flags)
        if saves:
            msg += f"\nWARNING: {saves} may contain game saves."
        if not recycle:
            msg += "\n\nThis cannot be undone."
        if not messagebox.askyesno("Confirm", msg, icon="warning", default="no"):
            return
        failed = []
        for n, it in enumerate(sel, 1):
            self.status.set(f"Deleting {n}/{len(sel)}: {it.name}")
            self.update_idletasks()
            try:
                (to_recycle_bin if recycle else delete_permanently)(it.path)
                if os.path.exists(it.path):
                    raise OSError("Folder still exists (some files may be locked)")
                self.trees[it.bucket].delete(it.path)
                self.items.pop(it.path, None)
                self.checked.discard(it.path)
            except Exception as ex:
                failed.append(f"{it.name}: {ex}")
        self._retitle()
        self._update_summary()
        self.status.set(f"Deleted {len(sel) - len(failed)} folders." + (f" {len(failed)} failed." if failed else ""))
        if failed:
            messagebox.showwarning("Some deletions failed", "\n".join(failed[:20]))


def _fatal(exc_text):
    """Double-click launches (.pyw) have no console, so log AND try a message box."""
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- {datetime.datetime.now()} ---\n{exc_text}\n")
    except Exception:
        log_path = None
    try:
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror("Folder Forensics - error",
                             exc_text + (f"\n\n(also written to {log_path})" if log_path else ""))
    except Exception:
        print(exc_text)


if __name__ == "__main__":
    try:
        if os.name != "nt" or winreg is None:
            raise RuntimeError("Folder Forensics only runs on Windows (it needs the built-in winreg module).")
        App().mainloop()
    except Exception:
        import traceback
        _fatal(traceback.format_exc())
        sys.exit(1)

#!/usr/bin/env python3
"""Inspect optional and required tools for a VulnHunter execution profile."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

CONFIG = json.loads((Path(__file__).resolve().parents[1] / "config" / "tools.json").read_text(encoding="utf-8"))
PROFILE_AGENTS = {
    "plan-only": ("report",),
    "passive-osint": ("recon", "crawl", "report"),
    "active-safe": ("recon", "crawl", "report"),
    "scanner-safe": ("recon", "crawl", "discovery", "scan", "report"),
}
PROBE = {
    "subfinder": ("-version", False),
    "dnsx": ("-version", False),
    "httpx": ("-version", False),
    "nuclei": ("-version", False),
    "gau": ("-version", True),
    "ffuf": ("-V", False),
    "naabu": ("-version", False),
    "dalfox": ("version", False),
    "gf": ("-h", True),
    "interactsh-client": ("-h", True),
    "arjun": ("-h", True),
    "waymore": ("--version", True),
    "uro": ("-h", True),
    "gotator": ("-h", True),
    "jsluice": ("-h", True),
    "gobuster": ("-h", False),
    "rustscan": ("--version", False),
    "feroxbuster": ("--version", False),
    "jq": ("--version", False),
    "curl": ("--version", False),
    "python3": ("--version", False),
}


def probe(name: str) -> tuple[bool, str]:
    binary = shutil.which(name)
    if not binary:
        return False, "not found"
    flag, allow_nonzero = PROBE.get(name, ("-h", True))
    try:
        process = subprocess.run([binary, flag], capture_output=True, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except OSError as exc:
        return False, str(exc)
    output = (process.stdout + process.stderr).decode("utf-8", "replace").strip()
    ok = process.returncode == 0 or allow_nonzero
    # Some naabu builds emit a fatal router-initialization error while still
    # returning success from `-version`. Do not present that binary as ready for
    # the approved port-scan stage.
    if name == "naabu" and re.search(r"(?:\b(?:err|error|fatal)\b|could not initialize)", output, re.IGNORECASE):
        ok = False
    note = output.splitlines()[0][:100] if output else f"exit={process.returncode}"
    return ok, note


def module_available(name: str) -> bool:
    """True if `name` is importable by the interpreter the orchestrator uses."""
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def scrapling_ok() -> tuple[bool, str]:
    launcher = Path(__file__).parent / "scrapling_crawl.sh"
    if not launcher.exists():
        return False, "launcher missing"
    override = os.environ.get("VHS_SCRAPLING_PYTHON")
    if override:
        venv_py = Path(override).expanduser()
    else:
        venv_home = os.environ.get("VHS_SCRAPLING_HOME", "/home/tomz/tools/scrapling/venv")
        venv_py = Path(venv_home).expanduser() / "bin" / "python"
    if not venv_py.exists():
        return False, f"venv python missing ({venv_py})"
    try:
        proc = subprocess.run(
            ["env", "-u", "PYTHONPATH", str(venv_py), "-c", "import scrapling; print('ok')"],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "venv python probe failed"
    ok = proc.returncode == 0 and b"ok" in proc.stdout
    return ok, "venv import ok" if ok else (proc.stderr.decode(errors="replace").strip()[:80] or "import failed")


def crawl4ai_ok() -> tuple[bool, str]:
    launcher = Path(__file__).parent / "crawl4ai_crawl.sh"
    if not launcher.exists():
        return False, "launcher missing"
    override = os.environ.get("VHS_CRAWL4AI_PYTHON")
    if override:
        venv_py = Path(override).expanduser()
    else:
        venv_home = os.environ.get("VHS_CRAWL4AI_HOME", "/home/tomz/tools/crawl4ai")
        venv_py = Path(venv_home).expanduser() / "bin" / "python"
    if not venv_py.exists():
        return False, f"venv python missing ({venv_py})"
    try:
        proc = subprocess.run(
            ["env", "-u", "PYTHONPATH", str(venv_py), "-c", "import crawl4ai; print('ok')"],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "venv python probe failed"
    ok = proc.returncode == 0 and b"ok" in proc.stdout
    return ok, "venv import ok" if ok else (proc.stderr.decode(errors="replace").strip()[:80] or "import failed")


def wafw00f_ok() -> tuple[bool, str]:
    launcher = Path(__file__).parent / "wafw00f.sh"
    if not launcher.exists():
        return False, "launcher missing"
    override = os.environ.get("VHS_WAFW00F_HOME")
    venv_home = Path(override).expanduser() if override else Path("/home/tomz/tools/wafw00f")
    binary = venv_home / "bin" / "wafw00f"
    if not binary.exists():
        return False, f"venv binary missing ({binary})"
    try:
        proc = subprocess.run(
            ["env", "-u", "PYTHONPATH", str(binary), "--version"],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "venv probe failed"
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    ok = proc.returncode == 0 and "wafw00f" in out.lower()
    return ok, "venv ok" if ok else (out.strip().splitlines()[0][:80] if out.strip() else "probe failed")


def venv_bin_ok(name: str, default_home: str, env_key: str, probe_arg: str = "--version") -> tuple[bool, str]:
    """Check a tool installed in a dedicated venv (PEP 668-safe pattern)."""
    override = os.environ.get(env_key)
    home = Path(override).expanduser() if override else Path(default_home)
    binary = home / "bin" / name
    if not binary.exists():
        return False, f"venv binary missing ({binary})"
    try:
        proc = subprocess.run(
            ["env", "-u", "PYTHONPATH", str(binary), probe_arg],
            capture_output=True, timeout=25, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "venv probe failed"
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    ok = proc.returncode == 0
    note = out.strip().splitlines()[0][:80] if out.strip() else f"exit={proc.returncode}"
    return ok, note


def sqlmap_ok() -> tuple[bool, str]:
    return venv_bin_ok("sqlmap", "/home/tomz/tools/sqlmap", "VHS_SQLMAP_HOME")


def paramspider_ok() -> tuple[bool, str]:
    return venv_bin_ok("paramspider", "/home/tomz/tools/paramspider", "VHS_PARAMSPIDER_HOME", "-h")


def nikto_ok() -> tuple[bool, str]:
    override = os.environ.get("VHS_NIKTO_HOME")
    home = Path(override).expanduser() if override else Path("/home/tomz/tools/nikto")
    program = home / "program" / "nikto.pl"
    if not program.exists():
        return False, f"nikto.pl missing ({program})"
    try:
        proc = subprocess.run(
            ["perl", str(program), "-Version"],
            capture_output=True, timeout=30, check=False,
            env={**os.environ, "PERL5LIB": os.environ.get("PERL5LIB", "") + ":/home/tomz/perl5/lib/perl5"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "nikto probe failed"
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    ok = proc.returncode == 0 and "nikto" in out.lower()
    return ok, out.strip().splitlines()[0][:80] if out.strip() else "probe failed"


SPECIAL_DETECT = {
    "scrapling": scrapling_ok,
    "crawl4ai": crawl4ai_ok,
    "wafw00f": wafw00f_ok,
    "sqlmap": sqlmap_ok,
    "paramspider": paramspider_ok,
    "nikto": nikto_ok,
}


def detect(name: str) -> tuple[bool, str]:
    """Binary lookup for CLIs, module/venv lookup for the python crawlers."""
    if name in SPECIAL_DETECT:
        return SPECIAL_DETECT[name]()
    binary = shutil.which(name)
    return (binary is not None), ("present" if binary is not None else "not found")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILE_AGENTS), default="scanner-safe")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results: dict[str, object] = {"profile": args.profile, "agents": {}}
    missing_required = False
    selected_agents = PROFILE_AGENTS[args.profile]
    for agent in selected_agents:
        spec = CONFIG[agent]
        required = list(spec.get("required_any") or [])
        optional = list(spec.get("optional") or [])
        available_required = [name for name in required if detect(name)[0]]
        if required and not available_required:
            missing_required = True
        results["agents"][agent] = {
            "required_any": {name: detect(name)[0] for name in required},
            "optional": {name: detect(name)[0] for name in optional},
        }
        if not args.json:
            requirement = ", ".join(available_required) if available_required else ("none" if not required else "MISSING")
            print(f"[{agent}] required-any: {requirement}")
            if optional:
                print("  optional: " + ", ".join(f"{name}={'yes' if detect(name)[0] else 'no'}" for name in optional))

    if args.verify:
        names = sorted({name for agent in selected_agents for name in CONFIG[agent].get("required_any", []) + CONFIG[agent].get("optional", [])})
        verification = {}
        for name in names:
            if name in SPECIAL_DETECT:
                ok, note = detect(name)
                verification[name] = {"present": True, "ok": ok, "note": note}
                if not args.json:
                    print(f"  [verify] {name:18s} {'OK' if ok else 'FAIL':4s} {note}")
                continue
            ok, note = probe(name)
            verification[name] = {"present": shutil.which(name) is not None, "ok": ok, "note": note}
            if not args.json:
                print(f"  [verify] {name:18s} {'OK' if ok else 'FAIL':4s} {note}")
        results["verification"] = verification

    if args.json:
        print(json.dumps(results, indent=2))
    return 2 if missing_required else 0


if __name__ == "__main__":
    raise SystemExit(main())

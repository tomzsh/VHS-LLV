#!/usr/bin/env python3
"""Fail-closed, resumable orchestrator for authorized security reconnaissance.

The runner coordinates collection and scanner tools. Tool matches remain unverified
until the engagement's controlled-validation phase is completed.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import importlib.util
import json
import os
import tempfile
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

from policy import PROFILE_RANK, PolicyError, ScopePolicy, authorize_run, normalize_host


@dataclass
class Step:
    agent: str
    tool: str
    status: str
    seconds: float
    output: str = ""
    note: str = ""
    command: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    """Atomically replace *path* using a unique temporary file in the same directory.

    A unique name is required because separate orchestrator processes and worker
    threads may write different artifacts at the same time. Keeping the temporary
    file in the destination directory preserves atomic os.replace() semantics.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.{os.getpid()}.",
        suffix=".tmp",
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            tmp.chmod(mode)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def clean_domain(raw: str) -> str:
    value = normalize_host(raw)
    if not value or "." not in value:
        raise argparse.ArgumentTypeError("target must be a valid DNS domain, e.g. example.com")
    return value


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def python_module_available(name: str) -> bool:
    """Return whether the orchestrator interpreter can import an optional module."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def crawl4ai_launcher_available(script: Path) -> bool:
    """Check the configured crawl4ai interpreter before scheduling the crawler."""
    override = os.environ.get("VHS_CRAWL4AI_PYTHON")
    if override:
        interpreter = Path(override).expanduser()
    else:
        home = os.environ.get("VHS_CRAWL4AI_HOME", "~/tools/crawl4ai")
        interpreter = Path(home).expanduser() / "bin" / "python"
    return script.exists() and os.access(script, os.X_OK) and interpreter.is_file() and os.access(interpreter, os.X_OK)


def redact_command(cmd: list[str]) -> list[str]:
    sensitive_flags = {"-h", "--header", "-cookie", "--cookie", "-token", "--token", "--api-key"}
    result: list[str] = []
    redact_next = False
    for part in cmd:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
        else:
            result.append(part)
            redact_next = part.lower() in sensitive_flags
    return result


def research_header_args(ctx: dict) -> list[str]:
    """Return the explicit, program-required research header for HTTP tools."""
    header = str(ctx.get("research_header") or "").strip()
    return ["-H", header] if header else []


def run_command(
    agent: str,
    tool: str,
    cmd: list[str],
    *,
    timeout: int,
    output: Path | None = None,
) -> Step:
    start = time.monotonic()
    output_handle = None
    try:
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output_handle = output.open("wb")
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=output_handle if output_handle else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        status = "ok" if proc.returncode == 0 else "error"
        stderr = proc.stderr.decode("utf-8", "replace")
        note = "\n".join(stderr.splitlines()[-30:])[-2000:].strip()
        if not output and proc.stdout:
            note = (proc.stdout.decode("utf-8", "replace") + "\n" + note).strip()[-2000:]
    except subprocess.TimeoutExpired:
        status, note = "timeout", f"exceeded {timeout}s"
    except OSError as exc:
        status, note = "error", str(exc)
    finally:
        if output_handle:
            output_handle.close()
    return Step(
        agent=agent,
        tool=tool,
        status=status,
        seconds=time.monotonic() - start,
        output=str(output) if output else "",
        note=note,
        command=redact_command(cmd),
    )


def unique_lines(inputs: Iterable[Path], output: Path) -> int:
    values: set[str] = set()
    for path in inputs:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                values.add(value)
    atomic_write(output, "".join(f"{value}\n" for value in sorted(values)))
    return len(values)


def filter_hosts(src: Path, dst: Path, policy: ScopePolicy) -> int:
    hosts: set[str] = set()
    if src.exists():
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            host = normalize_host(line)
            if host and policy.host_allowed(host):
                hosts.add(host)
    atomic_write(dst, "".join(f"{host}\n" for host in sorted(hosts)))
    return len(hosts)


def filter_urls(src: Path, dst: Path, policy: ScopePolicy) -> int:
    urls: set[str] = set()
    if src.exists():
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if not policy.url_allowed(value):
                continue
            parsed = urlsplit(value)
            clean = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
            urls.add(clean)
    atomic_write(dst, "".join(f"{url}\n" for url in sorted(urls)))
    return len(urls)


def extract_json_urls(value: object) -> set[str]:
    """Return HTTP(S) URLs found recursively in a JSON-compatible value."""
    if isinstance(value, dict):
        urls: set[str] = set()
        for child in value.values():
            urls.update(extract_json_urls(child))
        return urls
    if isinstance(value, list):
        urls: set[str] = set()
        for child in value:
            urls.update(extract_json_urls(child))
        return urls
    if isinstance(value, str):
        candidate = value.strip()
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return set()
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            return {candidate}
    return set()


def collect_discovery_urls(directory: Path, policy: ScopePolicy, output: Path) -> int:
    """Write sorted, normalized, in-scope URLs emitted by active discovery tools."""
    urls: set[str] = set()
    sources = [directory / "arjun.json", *sorted(directory.glob("ffuf_*.json"))]
    for source in sources:
        if not source.exists():
            continue
        try:
            discovered = extract_json_urls(json.loads(source.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
        for value in discovered:
            if not policy.url_allowed(value):
                continue
            parsed = urlsplit(value)
            urls.add(urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")))
    atomic_write(output, "".join(f"{url}\n" for url in sorted(urls)))
    return len(urls)


def method_set(engagement: dict, key: str) -> set[str]:
    values = engagement.get(key) or []
    return {str(item).strip().lower().replace("-", "_") for item in values if str(item).strip()}


def enforce_method_permissions(engagement: dict, profile: str, ports: bool) -> None:
    allowed = method_set(engagement, "allowed_methods")
    prohibited = method_set(engagement, "prohibited_methods")
    scanner_names = {"automated_scanning", "scanner_safe", "nuclei", "ffuf", "dalfox", "arjun"}
    if profile == "scanner-safe":
        if prohibited & scanner_names:
            raise PolicyError("engagement explicitly prohibits automated scanning")
        if not allowed.intersection(scanner_names):
            raise PolicyError(
                "scanner-safe requires explicit allowed_methods entry such as 'automated_scanning'"
            )
    if ports:
        if {"port_scan", "naabu"} & prohibited:
            raise PolicyError("engagement explicitly prohibits port scanning")
        if not ({"port_scan", "naabu"} & allowed):
            raise PolicyError("--ports requires explicit allowed_methods entry 'port_scan' or 'naabu'")


def write_hosts_seed(target: str, path: Path) -> None:
    atomic_write(path, target + "\n")


def passive_recon(ctx: dict) -> list[Step]:
    out, target, policy = ctx["out"], ctx["target"], ctx["policy"]
    directory = out / "agents" / "recon"
    directory.mkdir(parents=True, exist_ok=True)
    steps: list[Step] = []
    sources: list[Path] = []
    commands: list[tuple[str, list[str], Path, int]] = []
    if command_exists("subfinder"):
        commands.append(("subfinder", ["subfinder", "-d", target, "-all", "-silent"], directory / "subfinder.txt", min(180, ctx["agent_timeout"])))
    if command_exists("assetfinder"):
        commands.append(("assetfinder", ["assetfinder", "--subs-only", target], directory / "assetfinder.txt", min(120, ctx["agent_timeout"])))
    if command_exists("amass"):
        commands.append(("amass", ["amass", "enum", "-passive", "-d", target], directory / "amass.txt", min(300, ctx["agent_timeout"])))
    for tool, command, output, timeout in commands:
        step = run_command("recon", tool, command, timeout=timeout, output=output)
        steps.append(step)
        if output.exists():
            sources.append(output)
    seed = directory / "seed.txt"
    write_hosts_seed(target, seed)
    sources.append(seed)
    raw = directory / "hosts_raw.txt"
    unique_lines(sources, raw)
    scoped = directory / "hosts_scoped.txt"
    count = filter_hosts(raw, scoped, policy)
    steps.append(Step("recon", "scope-guard-hosts", "ok", 0, str(scoped), f"{count} host(s) allowed"))
    return steps


def active_recon(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    directory = out / "agents" / "recon"
    scoped = directory / "hosts_scoped.txt"
    resolved = directory / "hosts_resolved.txt"
    steps: list[Step] = []
    if command_exists("dnsx") and scoped.exists() and scoped.stat().st_size:
        steps.append(run_command("recon", "dnsx", ["dnsx", "-l", str(scoped), "-silent"], timeout=180, output=resolved))
        filter_hosts(resolved, resolved, policy)
    else:
        shutil.copyfile(scoped, resolved)
    live_json = directory / "httpx.jsonl"
    live_raw = directory / "live_urls_raw.txt"
    live_scoped = directory / "live_urls.txt"
    if command_exists("httpx") and resolved.exists() and resolved.stat().st_size:
        cmd = [
            "httpx", "-l", str(resolved), "-silent", "-json", "-status-code", "-title",
            "-tech-detect", "-content-type", "-follow-host-redirects", "-rate-limit",
            str(ctx["rate_http"]), "-timeout", str(ctx["timeout"]), "-retries", "1",
        ] + research_header_args(ctx) + ["-fc", "404"]
        steps.append(run_command("recon", "httpx", cmd, timeout=ctx["agent_timeout"], output=live_json))
        urls: set[str] = set()
        if live_json.exists():
            for line in live_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                value = item.get("url") or item.get("input")
                if value:
                    urls.add(str(value))
        atomic_write(live_raw, "".join(f"{url}\n" for url in sorted(urls)))
        count = filter_urls(live_raw, live_scoped, policy)
        steps.append(Step("recon", "scope-guard-live-urls", "ok", 0, str(live_scoped), f"{count} URL(s) allowed"))
    else:
        atomic_write(live_scoped, "")
    if ctx["ports"] and command_exists("naabu") and resolved.exists() and resolved.stat().st_size:
        command = [
            "naabu", "-list", str(resolved), "-silent", "-top-ports", "100", "-rate", str(ctx["rate_ports"])
        ]
        steps.append(run_command("recon", "naabu", command, timeout=ctx["agent_timeout"], output=directory / "ports.txt"))
    return steps


def passive_crawl(ctx: dict) -> list[Step]:
    out, target, policy = ctx["out"], ctx["target"], ctx["policy"]
    directory = out / "agents" / "crawl"
    directory.mkdir(parents=True, exist_ok=True)
    steps: list[Step] = []
    sources: list[Path] = []
    if command_exists("gau"):
        output = directory / "gau.txt"
        steps.append(run_command("crawl", "gau", ["gau", "--providers", "wayback,otx,commoncrawl,urlscan", target], timeout=min(180, ctx["agent_timeout"]), output=output))
        sources.append(output)
    if command_exists("waymore"):
        output = directory / "waymore.txt"
        step = run_command("crawl", "waymore", ["waymore", "-i", target, "-mode", "U", "-oU", str(output)], timeout=min(300, ctx["agent_timeout"]))
        step.output = str(output)
        steps.append(step)
        sources.append(output)
    raw = directory / "urls_raw.txt"
    unique_lines(sources, raw)
    scoped = directory / "urls_scoped.txt"
    count = filter_urls(raw, scoped, policy)
    steps.append(Step("crawl", "scope-guard-passive-urls", "ok", 0, str(scoped), f"{count} URL(s) allowed"))
    return steps


def active_crawl(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    directory = out / "agents" / "crawl"
    live = out / "agents" / "recon" / "live_urls.txt"
    passive = directory / "urls_scoped.txt"
    steps: list[Step] = []
    sources = [passive]
    if command_exists("katana") and live.exists() and live.stat().st_size:
        output = directory / "katana.txt"
        command = [
            "katana", "-list", str(live), "-silent", "-jc", "-kf", "all", "-d", "3",
            "-rl", str(ctx["rate_http"]),
        ] + research_header_args(ctx)
        steps.append(run_command("crawl", "katana", command, timeout=ctx["agent_timeout"], output=output))
        sources.append(output)
    # Scrapling stealth fetch (live JS/anti-bot pages that plain HTTP misses).
    if live.exists() and live.stat().st_size:
        scrapling_script = Path(__file__).parent / "scrapling_crawl.py"
        if ctx.get("research_header"):
            # These optional crawlers do not consistently support a caller-supplied
            # header. Skipping preserves program rules that require attribution on
            # unauthenticated requests.
            if scrapling_script.exists():
                steps.append(Step("crawl", "scrapling", "skipped", 0, "", "required research header unsupported"))
        elif scrapling_script.exists() and command_exists("python3") and python_module_available("scrapling"):
            s_out = directory / "scrapling.txt"
            steps.append(run_command(
                "crawl", "scrapling",
                [sys.executable, str(scrapling_script), "--input", str(live), "--output", str(s_out)],
                timeout=ctx["agent_timeout"]))
            sources.append(s_out)
        elif scrapling_script.exists():
            steps.append(Step("crawl", "scrapling", "skipped", 0, "", "module not importable by python3"))
        # crawl4ai headless-browser crawl (JS rendering + link discovery).
        crawl4ai_script = Path(__file__).parent / "crawl4ai_crawl.sh"
        if ctx.get("research_header"):
            if crawl4ai_script.exists():
                steps.append(Step("crawl", "crawl4ai", "skipped", 0, "", "required research header unsupported"))
        elif crawl4ai_launcher_available(crawl4ai_script):
            c4_out = directory / "crawl4ai.txt"
            steps.append(run_command(
                "crawl", "crawl4ai",
                [str(crawl4ai_script), "--input", str(live), "--output", str(c4_out)],
                timeout=ctx["agent_timeout"]))
            sources.append(c4_out)
        elif crawl4ai_script.exists():
            steps.append(Step("crawl", "crawl4ai", "skipped", 0, "", "configured venv python unavailable"))
    combined_raw = directory / "urls_all_raw.txt"
    unique_lines(sources, combined_raw)
    combined = directory / "urls_all.txt"
    count = filter_urls(combined_raw, combined, policy)
    steps.append(Step("crawl", "scope-guard-all-urls", "ok", 0, str(combined), f"{count} URL(s) allowed"))
    javascript: list[str] = []
    api: list[str] = []
    if combined.exists():
        for line in combined.read_text(encoding="utf-8", errors="ignore").splitlines():
            low = line.lower()
            if low.split("?", 1)[0].endswith(".js"):
                javascript.append(line)
            if any(marker in low for marker in ("/api/", "/graphql", "/v1/", "/v2/", "/v3/", "/webhook", "/callback")):
                api.append(line)
    atomic_write(directory / "javascript_urls.txt", "".join(f"{x}\n" for x in sorted(set(javascript))))
    atomic_write(directory / "api_candidates.txt", "".join(f"{x}\n" for x in sorted(set(api))))
    return steps


def normalize_discovery(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    directory = out / "agents" / "discovery"
    directory.mkdir(parents=True, exist_ok=True)
    active_source = out / "agents" / "crawl" / "urls_all.txt"
    passive_source = out / "agents" / "crawl" / "urls_scoped.txt"
    source = active_source if active_source.exists() else passive_source
    raw = directory / "urls_normalized_raw.txt"
    output = directory / "urls_normalized.txt"
    steps: list[Step] = []
    if command_exists("uro") and source.exists() and source.stat().st_size:
        steps.append(run_command("discovery", "uro", ["uro", "-i", str(source)], timeout=min(120, ctx["agent_timeout"]), output=raw))
    else:
        unique_lines([source], raw)
    count = filter_urls(raw, output, policy)
    steps.append(Step("discovery", "scope-guard-normalized-urls", "ok", 0, str(output), f"{count} URL(s) allowed"))
    return steps


def active_discovery(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    directory = out / "agents" / "discovery"
    live = out / "agents" / "recon" / "live_urls.txt"
    steps: list[Step] = []
    targets = live.read_text(encoding="utf-8", errors="ignore").splitlines()[: ctx["max_hosts"]] if live.exists() else []
    if command_exists("arjun") and targets:
        limited = directory / "arjun_targets.txt"
        atomic_write(limited, "".join(f"{url}\n" for url in targets))
        output = directory / "arjun.json"
        command = ["arjun", "-i", str(limited), "-oJ", str(output), "--rate-limit", str(max(1, ctx["rate_discovery"]))]
        step = run_command("discovery", "arjun", command, timeout=ctx["agent_timeout"])
        step.output = str(output)
        steps.append(step)
    if command_exists("ffuf") and ctx["wordlist"] and targets:
        for index, url in enumerate(targets, 1):
            identifier = hashlib.sha256(url.encode()).hexdigest()[:12]
            output = directory / f"ffuf_{identifier}.json"
            command = [
                "ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", str(ctx["wordlist"]), "-ac",
                "-t", "10", "-rate", str(ctx["rate_discovery"]), "-timeout", str(ctx["timeout"]),
                "-of", "json", "-o", str(output),
            ]
            step = run_command("discovery", f"ffuf[{index}]", command, timeout=ctx["agent_timeout"])
            step.output = str(output)
            steps.append(step)
    output = directory / "urls_discovered.txt"
    count = collect_discovery_urls(directory, policy, output)
    steps.append(Step("discovery", "scope-guard-discovered-urls", "ok", 0, str(output), f"{count} URL(s) allowed"))
    return steps


def capture_baselines(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    live = out / "agents" / "recon" / "live_urls.txt"
    output = out / "agents" / "recon" / "baselines.json"
    if not command_exists("curl") or not live.exists():
        atomic_write(output, "{}\n")
        return [Step("recon", "soft404-baseline", "skipped", 0, str(output), "curl unavailable or no live URLs")]
    baselines: dict[str, dict[str, object]] = {}
    steps: list[Step] = []
    for url in live.read_text(encoding="utf-8", errors="ignore").splitlines()[: ctx["max_hosts"]]:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        probe_url = origin + "/.vulnhunter-not-found-" + uuid.uuid4().hex
        if not policy.url_allowed(probe_url):
            continue
        temp = output.parent / ("baseline-" + hashlib.sha256(origin.encode()).hexdigest()[:12] + ".txt")
        command = [
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
            "--max-time", str(ctx["timeout"]), "--max-redirs", "0",
        ] + research_header_args(ctx) + [probe_url]
        step = run_command("recon", "soft404-baseline", command, timeout=ctx["timeout"] + 5, output=temp)
        step.output = str(output)
        step.note = (f"origin={origin}; " + step.note).strip()
        steps.append(step)
        try:
            status, size = temp.read_text(encoding="utf-8").strip().split()
            baselines[origin] = {"status": status, "size": int(float(size)), "probe_url": probe_url}
        except (OSError, ValueError):
            pass
        temp.unlink(missing_ok=True)
    atomic_write(output, json.dumps(baselines, indent=2) + "\n")
    return steps or [Step("recon", "soft404-baseline", "skipped", 0, str(output), "no eligible targets")]


def nuclei_scan(ctx: dict) -> list[Step]:
    out = ctx["out"]
    directory = out / "agents" / "scan"
    directory.mkdir(parents=True, exist_ok=True)
    live = out / "agents" / "recon" / "live_urls.txt"
    if not command_exists("nuclei") or not live.exists() or not live.stat().st_size:
        return [Step("scan", "nuclei", "skipped", 0, "", "nuclei unavailable or no live scoped URLs")]
    targets = live.read_text(encoding="utf-8", errors="ignore").splitlines()[: ctx["max_hosts"]]
    limited = directory / "nuclei_targets.txt"
    atomic_write(limited, "".join(f"{url}\n" for url in targets))
    output = directory / "nuclei.jsonl"
    command = [
        "nuclei", "-l", str(limited), "-severity", ctx["severity"], "-etags", "dos,fuzz",
        "-retries", "1", "-rl", str(ctx["rate_scan"]), "-bulk-size", "10", "-concurrency", "10",
        "-jsonl", "-o", str(output),
    ]
    if not ctx["enable_oast"]:
        command.append("-ni")
    step = run_command("scan", "nuclei", command, timeout=ctx["agent_timeout"])
    step.output = str(output)
    return [step]


def dalfox_scan(ctx: dict) -> list[Step]:
    out, policy = ctx["out"], ctx["policy"]
    directory = out / "agents" / "scan"
    normalized = out / "agents" / "discovery" / "urls_normalized.txt"
    discovered = out / "agents" / "discovery" / "urls_discovered.txt"
    candidates = directory / "xss_candidates.txt"
    values: set[str] = set()
    for source in (normalized, discovered):
        if not source.exists():
            continue
        for line in source.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if "=" in value and policy.url_allowed(value):
                values.add(value)
    atomic_write(candidates, "".join(f"{url}\n" for url in sorted(values)))
    if not command_exists("dalfox"):
        return [Step("scan", "dalfox", "skipped", 0, str(candidates), "dalfox unavailable")]
    if not values:
        return [Step("scan", "dalfox", "skipped", 0, str(candidates), "no parameterized URLs")]
    output = directory / "dalfox.txt"
    command = [
        "dalfox", "file", str(candidates), "--silence", "--only-poc", "--worker", "5",
        "--output", str(output),
    ]
    step = run_command("scan", "dalfox", command, timeout=ctx["agent_timeout"])
    step.output = str(output)
    return [step]


def file_count(path: Path) -> int:
    try:
        if path.suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                if isinstance(data.get("results"), list):
                    return len(data["results"])
                return len(data)
        return sum(1 for line in path.open(encoding="utf-8", errors="ignore") if line.strip())
    except (OSError, json.JSONDecodeError):
        return 0


def report(ctx: dict, steps: list[Step]) -> None:
    out = ctx["out"]
    counts: dict[str, int] = {}
    for path in out.glob("agents/**/*"):
        if path.is_file() and path.suffix in {".txt", ".json", ".jsonl", ".csv"}:
            counts[str(path.relative_to(out))] = file_count(path)
    engagement = ctx.get("engagement") or {}
    manifest = {
        "schema_version": 2,
        "target": ctx["target"],
        "profile": ctx["profile"],
        "created_at": ctx["started"],
        "finished_at": utc_now(),
        "authorized_only": ctx["profile"] != "plan-only",
        "authorization": {
            "verified": ctx["profile"] != "plan-only",
            "engagement_id": engagement.get("engagement_id"),
            "authorization_status": engagement.get("authorization_status"),
            "permission_mode": engagement.get("permission_mode"),
            "scope_verified": ctx["profile"] != "plan-only",
            "testing_window_verified": ctx["profile"] != "plan-only",
        },
        "outputs": {
            "nuclei": "agents/scan/nuclei.jsonl",
            "baselines": "agents/recon/baselines.json",
            "live_urls": "agents/recon/live_urls.txt",
            "normalized_urls": "agents/discovery/urls_normalized.txt",
        },
        "steps": [asdict(step) for step in steps],
        "counts": counts,
        "limitations": [
            "Scanner matches are unverified and must not be reported as confirmed findings.",
            (
                "OAST templates were disabled." if not ctx.get("enable_oast")
                else "OAST was explicitly enabled by the operator."
            ) if ctx["profile"] == "scanner-safe" else "No scanner phase was requested.",
        ],
    }
    atomic_write(out / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    lines = [
        f"# VulnHunter run — {ctx['target']}", "",
        f"- Execution profile: `{ctx['profile']}`",
        f"- Authorization verified: `{manifest['authorization']['verified']}`", "",
        "> Scanner output is unverified. Complete P4 baseline, mutation, negative-control, and evidence checks before reporting.",
        "", "## Agent status", "",
    ]
    for step in steps:
        suffix = f" — {step.note[:180]}" if step.note else ""
        lines.append(f"- **{step.agent}/{step.tool}** — `{step.status}` ({step.seconds:.1f}s){suffix}")
    lines.extend(["", "## Output counts", ""])
    lines.extend(f"- `{name}`: {count}" for name, count in sorted(counts.items()))
    atomic_write(out / "SUMMARY.md", "\n".join(lines) + "\n")


def config_fingerprint(ctx: dict) -> str:
    stable = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in ctx.items()
        if key not in {"out", "started", "policy", "engagement", "state", "resume"}
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def authorization_fingerprint(
    engagement: dict, state: dict, scope_file: Path | None
) -> str:
    projection = {
        "engagement": {
            key: engagement.get(key)
            for key in (
                "authorization_status", "permission_mode", "allowed_assets",
                "excluded_assets", "allowed_methods", "prohibited_methods",
                "testing_window", "rate_limits", "stop_conditions",
            )
        },
        "p0_status": ((state.get("phases") or {}).get("P0") or {}).get("status"),
        "scope_file_sha256": (
            hashlib.sha256(scope_file.read_bytes()).hexdigest()
            if scope_file and scope_file.is_file() else None
        ),
    }
    encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def checkpoint_rows_reusable(rows: object) -> list[Step] | None:
    if not isinstance(rows, list):
        return None
    try:
        parsed = [Step(**row) for row in rows]
    except (TypeError, ValueError):
        return None
    if any(item.status in {"error", "timeout"} for item in parsed):
        return None
    return parsed


@contextmanager
def run_lock(out: Path):
    """Hold an exclusive process lock for the entire run directory lifecycle.

    flock is released automatically by the kernel if the process exits, crashes,
    or is killed. The lock file stores owner metadata for diagnostics, but its mere
    existence is never treated as proof that a live process owns the lock.
    """
    lock = out / ".run.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    handle = lock.open("a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.seek(0)
            owner = handle.read().strip() or "owner metadata unavailable"
            raise RuntimeError(f"run directory is locked: {lock} ({owner})") from None

        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} created={utc_now()}\n")
        handle.flush()
        os.fsync(handle.fileno())
        try:
            os.fchmod(handle.fileno(), 0o600)
        except OSError:
            pass
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
        # Keep the inode in place. Its presence is harmless; only the kernel-held
        # advisory lock determines ownership. Unlinking here would introduce a
        # race where another process locks the old inode while a third creates a
        # new lock file at the same path.


def stage(ctx: dict, name: str, function: Callable[[dict], list[Step]]) -> list[Step]:
    stage_dir = ctx["out"] / "stages"
    stage_file = stage_dir / f"{name}.json"
    if ctx["resume"] and stage_file.exists():
        try:
            rows = json.loads(stage_file.read_text(encoding="utf-8"))
            reusable = checkpoint_rows_reusable(rows)
            if reusable is not None:
                return reusable
        except (json.JSONDecodeError, TypeError):
            pass
    result = function(ctx)
    atomic_write(stage_file, json.dumps([asdict(item) for item in result], indent=2) + "\n")
    return result


def plan_only(ctx: dict) -> list[Step]:
    out = ctx["out"]
    plan = {
        "target": ctx["target"],
        "profile": "plan-only",
        "target_traffic": False,
        "next_required_input": "A completed P0 engagement workspace is required for passive or active execution.",
        "available_profiles": list(PROFILE_RANK),
    }
    atomic_write(out / "EXECUTION_PLAN.json", json.dumps(plan, indent=2) + "\n")
    return [Step("policy", "plan-only", "ok", 0, str(out / "EXECUTION_PLAN.json"), "no network tools executed")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=clean_domain)
    parser.add_argument("--engagement", type=Path, help="P0 engagement directory; required for non-plan profiles")
    parser.add_argument("--profile", choices=tuple(PROFILE_RANK), default=None)
    parser.add_argument("--manual-only", action="store_true", help="compatibility alias for --profile passive-osint")
    parser.add_argument("--scope", type=Path, help="optional additional allow/deny rules; cannot expand engagement scope")
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--parallel", action="store_true", help="run discovery and nuclei concurrently; Dalfox waits for discovery")
    parser.add_argument("--ports", action="store_true", help="requires explicit port_scan permission in engagement.json")
    parser.add_argument("--resume", action="store_true", help="reuse completed stage checkpoints in an existing --out directory")
    parser.add_argument("--max-hosts", type=int, default=15)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--agent-timeout", type=int, default=300)
    parser.add_argument("--rate-http", type=int, default=25)
    parser.add_argument("--rate-discovery", type=int, default=10)
    parser.add_argument("--rate-scan", type=int, default=20)
    parser.add_argument("--rate-ports", type=int, default=50)
    parser.add_argument("--severity", default="critical,high")
    parser.add_argument("--enable-oast", action="store_true", help="explicitly enable Nuclei OAST/Interactsh coverage")
    parser.add_argument(
        "--research-header",
        help="explicit request header required by an authorized program, e.g. 'X-HackerOne-Research: username'",
    )
    args = parser.parse_args()

    env_manual = os.environ.get("VULNHUNTER_MANUAL_ONLY", "0") == "1"
    if (args.manual_only or env_manual) and args.profile and args.profile != "passive-osint":
        parser.error("manual-only mode conflicts with --profile")
    profile = "passive-osint" if (args.manual_only or env_manual) else (args.profile or "plan-only")
    if args.scope and not args.scope.is_file():
        parser.error("--scope file not found")
    if args.wordlist and not args.wordlist.is_file():
        parser.error("--wordlist file not found")
    if args.resume and not args.out:
        parser.error("--resume requires an explicit existing --out directory")
    if args.max_hosts < 1:
        parser.error("--max-hosts must be at least 1")
    for name in ("timeout", "agent_timeout", "rate_http", "rate_discovery", "rate_scan", "rate_ports"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be at least 1")

    engagement = state = None
    policy: ScopePolicy
    if profile == "plan-only":
        policy = ScopePolicy([args.target])
    else:
        if not args.engagement:
            parser.error("--engagement is required for passive-osint, active-safe, and scanner-safe")
        engagement_root = args.engagement.expanduser().resolve()
        # Auto-resolve a doubled engagement path. If the user is already inside
        # the engagement dir and passes --engagement ./engagement, the resolved
        # path becomes <cwd>/engagement which does NOT contain engagement.json
        # (it contains the phase dir or nothing). Detect the real root by walking
        # up until engagement.json exists; fall back to the literal path so the
        # original error remains clear if nothing matches.
        if not (engagement_root / "engagement.json").exists():
            candidate = engagement_root
            while not (candidate / "engagement.json").exists() and candidate != candidate.parent:
                candidate = candidate.parent
            if (candidate / "engagement.json").exists():
                engagement_root = candidate
        try:
            engagement, state, policy = authorize_run(engagement_root, args.target, profile, args.scope)
            enforce_method_permissions(engagement, profile, args.ports)
        except PolicyError as exc:
            parser.error(str(exc))

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out.expanduser().resolve() if args.out else Path.cwd() / "vulnhunter-runs" / args.target / timestamp
    if args.resume and not out.is_dir():
        parser.error("--resume --out directory does not exist")
    out.mkdir(parents=True, exist_ok=True)
    try:
        out.chmod(0o700)
    except OSError:
        pass

    ctx = {
        **vars(args),
        "profile": profile,
        "out": out,
        "policy": policy,
        "engagement": engagement,
        "state": state,
        "started": utc_now(),
    }
    ctx["authorization_fingerprint"] = authorization_fingerprint(
        engagement or {}, state or {}, args.scope
    )
    fingerprint = config_fingerprint(ctx)
    config_path = out / "run-config.json"
    config_record = {
        "fingerprint": fingerprint,
        "created_at": ctx["started"],
        "arguments": {
            key: ("<redacted>" if key == "research_header" and value else str(value) if isinstance(value, Path) else value)
            for key, value in vars(args).items()
        },
        "resolved_profile": profile,
    }
    print(f"Target: {args.target}\nProfile: {profile}\nOutput: {out}\n")
    steps: list[Step] = []
    try:
        # Acquire the process lock before the first mutable run artifact. This
        # protects run-config.json as well as every stage, report, and manifest.
        with run_lock(out):
            if args.resume and config_path.exists():
                previous = json.loads(config_path.read_text(encoding="utf-8"))
                if previous.get("fingerprint") != fingerprint:
                    raise RuntimeError("resume configuration differs from the original run")
            atomic_write(config_path, json.dumps(config_record, indent=2) + "\n")

            if profile == "plan-only":
                steps.extend(stage(ctx, "00-plan", plan_only))
            else:
                steps.extend(stage(ctx, "10-passive-recon", passive_recon))
                steps.extend(stage(ctx, "20-passive-crawl", passive_crawl))
                if PROFILE_RANK[profile] >= PROFILE_RANK["active-safe"]:
                    steps.extend(stage(ctx, "30-active-recon", active_recon))
                    steps.extend(stage(ctx, "40-active-crawl", active_crawl))
                    steps.extend(stage(ctx, "50-normalize", normalize_discovery))
                else:
                    # Passive profile still creates normalized, scope-filtered artifacts offline.
                    steps.extend(stage(ctx, "50-normalize", normalize_discovery))
                if profile == "scanner-safe":
                    steps.extend(stage(ctx, "55-baselines", capture_baselines))
                    if args.parallel:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                            discovery_future = executor.submit(stage, ctx, "60-active-discovery", active_discovery)
                            nuclei_future = executor.submit(stage, ctx, "70-nuclei", nuclei_scan)
                            steps.extend(discovery_future.result())
                            steps.extend(nuclei_future.result())
                    else:
                        steps.extend(stage(ctx, "60-active-discovery", active_discovery))
                        steps.extend(stage(ctx, "70-nuclei", nuclei_scan))
                    # Explicit dependency: Dalfox only starts after normalized/discovery output exists.
                    steps.extend(stage(ctx, "80-dalfox", dalfox_scan))
            report(ctx, steps)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    failures = sum(step.status in {"error", "timeout"} for step in steps)
    print(f"Done with {failures} non-fatal tool error(s). See {out / 'SUMMARY.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

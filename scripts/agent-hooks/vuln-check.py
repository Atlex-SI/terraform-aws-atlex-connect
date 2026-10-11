#!/usr/bin/env python3
"""Claude Code PreToolUse hook (Bash): check packages before they are installed.

Atlex rule C2 (docs/standards/core.md). For `pnpm add`, `npm install`, `yarn add`, `bun add`,
`pip install`, `uv add` and `uv pip install`, every named registry package is resolved to the
version that would be installed, then blocked if:
  - OSV (https://api.osv.dev) lists a known vulnerability for that version, or
  - that version was published less than MIN_AGE_DAYS ago.
A plain `pnpm install` / `npm ci` (lockfile only) is not checked. The hook fails closed: if a
registry or OSV can't be reached, the install is blocked with the reason. Exit 2 blocks the
command and tells the agent why; exit 0 lets it through. Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

MIN_AGE_DAYS = 14
TIMEOUT_S = 15
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
OSV_QUERY = "https://api.osv.dev/v1/query"
WORKSPACE_SCOPE = "@atlex/"

NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add"}
INSTALL_SUBCOMMANDS = {
    "pnpm": {"add", "install", "i"},
    "npm": NPM_INSTALL,
    "yarn": {"add"},
    "bun": {"add", "install", "i"},
    "pip": {"install"},
    "uv": {"add"},
}
# Flags whose next token is a value, not a package.
VALUE_FLAGS = {
    "-C", "--dir", "-F", "--filter", "--registry", "--reporter", "--tag", "-w", "--workspace",
    "--prefix", "--cwd", "-r", "--requirement", "--requirements", "-c", "--constraint",
    "--constraints", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "--index",
    "--default-index", "-f", "--find-links", "-t", "--target", "--python", "-p", "--group",
    "--optional", "--package", "--extra", "--root", "--platform", "--python-version",
}
# `pnpm -w` and `npm -w` differ: pnpm's is a boolean.
PNPM_BOOLEAN = {"-w"}
COMMAND_PREFIXES = {"sudo", "corepack", "command", "exec", "time", "nice", "env"}
SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")", "\n"}
INSTALL_HINT = re.compile(r"\b(pnpm|npm|yarn|bun|pip3?|uv)\b[^\n;&|]*\b(add|install|i)\b")


class Blocked(Exception):
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


def get_json(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
        return json.load(response)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def numeric(version: str) -> tuple[int, ...] | None:
    """Sort key for plain release versions (1.2.3); None for pre-releases and odd shapes."""
    if not re.fullmatch(r"\d+(\.\d+)*", version):
        return None
    return tuple(int(part) for part in version.split("."))


def newest_old_enough(published: dict[str, datetime]) -> str | None:
    cutoff = now() - timedelta(days=MIN_AGE_DAYS)
    candidates = [v for v, t in published.items() if t <= cutoff and numeric(v) is not None]
    return max(candidates, key=lambda v: numeric(v) or ()) if candidates else None


def osv_vulns(ecosystem: str, name: str, version: str) -> list[str]:
    result = get_json(OSV_QUERY, {"package": {"name": name, "ecosystem": ecosystem}, "version": version})
    vulns = result.get("vulns") or []
    return [f"{v.get('id')}: {v.get('summary') or 'no summary'}" for v in vulns]


def verdict(ecosystem: str, name: str, version: str, published: dict[str, datetime]) -> list[str]:
    problems = []
    when = published.get(version)
    if when is None:
        problems.append(f"{name}@{version}: no publish date on the registry")
    else:
        age = now() - when
        if age < timedelta(days=MIN_AGE_DAYS):
            hint = newest_old_enough(published)
            suggestion = f" Newest release older than {MIN_AGE_DAYS} days: {name}@{hint}." if hint else ""
            problems.append(
                f"{name}@{version} was published {age.days} day(s) ago (minimum {MIN_AGE_DAYS}).{suggestion}"
            )
    vulns = osv_vulns(ecosystem, name, version)
    if vulns:
        listed = "; ".join(vulns[:5]) + (f"; and {len(vulns) - 5} more" if len(vulns) > 5 else "")
        problems.append(f"{name}@{version} has {len(vulns)} known vulnerabilities in OSV: {listed}")
    return problems


# --- npm ---------------------------------------------------------------------------------------


def split_npm_spec(spec: str) -> tuple[str, str]:
    at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    return (spec, "") if at == -1 else (spec[:at], spec[at + 1 :])


def resolve_npm(name: str, wanted: str, packument: dict) -> str:
    tags = packument.get("dist-tags") or {}
    versions = packument.get("versions") or {}
    if not wanted:
        wanted = "latest"
    if wanted in tags:
        return tags[wanted]
    if wanted in versions:
        return wanted
    npm = shutil.which("npm")
    if npm is None:
        raise Blocked(f"{name}@{wanted}: can't resolve a range without npm; pin an exact version")
    try:
        out = subprocess.run(
            [npm, "view", f"{name}@{wanted}", "version", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError) as error:
        raise Blocked(f"{name}@{wanted}: couldn't resolve the range ({error}); pin an exact version")
    resolved = json.loads(out) if out.strip() else None
    if isinstance(resolved, list):
        resolved = resolved[-1] if resolved else None
    if not resolved:
        raise Blocked(f"{name}@{wanted}: no published version matches")
    return resolved


def check_npm(spec: str) -> list[str]:
    if spec.startswith((".", "/", "~")) or re.match(r"^(file|link|workspace|portal):", spec):
        return []  # local path or workspace package
    name, wanted = split_npm_spec(spec)
    if name.startswith(WORKSPACE_SCOPE) or wanted.startswith("workspace:"):
        return []
    if ":" in spec or "/" in name and not name.startswith("@"):
        raise Blocked(f"{spec}: git, URL and alias installs can't be checked; install a registry version")
    url = f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}"
    try:
        packument = get_json(url)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Blocked(f"{name}: not found on the npm registry")
        raise
    published = {v: parse_time(t) for v, t in (packument.get("time") or {}).items() if v not in ("created", "modified")}
    version = resolve_npm(name, wanted, packument)
    return verdict("npm", name, version, published)


# --- PyPI --------------------------------------------------------------------------------------

PY_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def check_pypi(spec: str) -> list[str]:
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith("git+") or " @ " in spec:
        raise Blocked(f"{spec}: path, URL and git installs can't be checked; install a PyPI release")
    match = PY_SPEC.match(spec.strip())
    if not match:
        raise Blocked(f"{spec}: couldn't parse the requirement; use name==version")
    name, _, constraint = match.groups()
    constraint = constraint.strip()
    try:
        info = get_json(f"{PYPI}/{urllib.parse.quote(name)}/json")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise Blocked(f"{name}: not found on PyPI")
        raise
    published = {}
    for version, files in (info.get("releases") or {}).items():
        times = [parse_time(f["upload_time_iso_8601"]) for f in files if f.get("upload_time_iso_8601")]
        if times:
            published[version] = min(times)
    pinned = re.fullmatch(r"===?\s*([^\s,;*]+)", constraint)
    if not constraint:
        version = (info.get("info") or {}).get("version") or ""
    elif pinned:
        version = pinned.group(1)
    else:
        raise Blocked(f"{name}{constraint}: pin an exact version (`{name}==<version>`) so it can be checked")
    return verdict("PyPI", name, version, published)


# --- command parsing ---------------------------------------------------------------------------


def segments(command: str) -> list[list[str]]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    current: list[str] = []
    result = [current]
    redirect_target = False
    for token in lexer:
        if redirect_target:
            redirect_target = False
        elif set(token) <= set("<>&") and ("<" in token or ">" in token):
            # A redirection such as `2>/dev/null`: drop the fd number and the target.
            if current and current[-1].isdigit():
                current.pop()
            redirect_target = not token.endswith("&") or token == ">&"
        elif token in SEPARATORS or set(token) <= set("&|;()"):
            current = []
            result.append(current)
        else:
            current.append(token)
    return [s for s in result if s]


def positionals(args: list[str], tool: str) -> list[str]:
    out, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-"):
            if "=" not in arg and arg in VALUE_FLAGS and not (tool == "pnpm" and arg in PNPM_BOOLEAN):
                skip = True
        else:
            out.append(arg)
    return out


def installs(tokens: list[str]) -> tuple[str, list[str]] | None:
    """Returns (ecosystem, package specs) if this command installs named packages."""
    while tokens and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0] in COMMAND_PREFIXES):
        tokens = tokens[1:]
    if not tokens:
        return None
    tool = os.path.basename(tokens[0])
    rest = tokens[1:]
    if re.fullmatch(r"python3?(\.\d+)?", tool) and rest[:2] == ["-m", "pip"]:
        tool, rest = "pip", rest[2:]
    elif tool == "pip3":
        tool = "pip"
    elif tool == "uv" and rest[:1] == ["pip"]:
        tool, rest = "pip", rest[1:]
    if tool not in INSTALL_SUBCOMMANDS:
        return None
    words = positionals(rest, tool)
    if not words or words[0] not in INSTALL_SUBCOMMANDS[tool]:
        return None
    specs = words[1:]
    return ("PyPI" if tool in ("pip", "uv") else "npm", specs) if specs else None


def check(command: str) -> int:
    try:
        parsed = segments(command)
    except ValueError:
        if INSTALL_HINT.search(command):
            raise Blocked("couldn't parse this command; run the install as its own simple command")
        return 0

    problems: list[str] = []
    for tokens in parsed:
        found = installs(tokens)
        if not found:
            continue
        ecosystem, specs = found
        for spec in specs:
            try:
                problems += check_pypi(spec) if ecosystem == "PyPI" else check_npm(spec)
            except Blocked as reason:
                problems.append(str(reason))
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as error:
                problems.append(f"{spec}: couldn't verify ({error}); retry, or ask the user to install it")
    if problems:
        raise Blocked("\n  - ".join([""] + problems))
    return 0


def block(reason: str) -> None:
    print(
        "Blocked by scripts/agent-hooks/vuln-check.py (Atlex rule C2: check a dependency "
        f"before installing it):{reason}",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    command = ""
    try:
        command = (json.load(sys.stdin).get("tool_input") or {}).get("command") or ""
        sys.exit(check(command))
    except Blocked as reason:
        block(str(reason))
    except Exception as error:  # A bug here must not block unrelated commands, only installs.
        if INSTALL_HINT.search(command):
            block(f" the check itself failed ({error!r}); fix the hook or ask the user to install it")
        sys.exit(0)

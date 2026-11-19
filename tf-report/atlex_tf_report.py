#!/usr/bin/env python3
"""atlex-tf-report: send Atlex a Terraform workspace's applied state, stripped on this runner.

Runs `terraform show -json` and `terraform state pull`, keeps only the allowlisted identity of
each managed resource, signs the result with this connection's secret and posts it to Atlex.
Nothing a state marks sensitive, and nothing off the allowlist, ever leaves this machine.

Python 3.9+ standard library only: no package is installed, so this file is the whole supply
chain. Read it before you run it; `--dry-run` prints exactly what would be sent.

Environment:
  ATLEX_CONNECTION_ID      the Terraform connection's ID (from the Atlex connect screen)
  ATLEX_TF_REPORT_SECRET   its tf-report secret (keep it in your CI's secret store)
  GITHUB_REPOSITORY        owner/name, set by GitHub Actions (or pass --repository)
  GITHUB_REPOSITORY_ID     the repository's numeric ID, set by GitHub Actions (or --repository-id)

Exit codes: 0 sent (or dry run), 1 nothing sent because of a problem here, 2 Atlex refused it.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

VERSION = "1.0.0"
FORMAT = "atlex-tf-report/1"
DEFAULT_ENDPOINT = "https://hooks.atlex.si/hooks/terraform"
SIGNATURE_PREFIX = "v1="
MAX_PACKED_BYTES = 4_000_000
MAX_RESOURCES = 20_000
TIMEOUT_SECONDS = 30

# Terraform AWS types whose live resource Atlex models: only these keep their ARN (else ID), since
# that's what links them to what Atlex crawled. Every other resource keeps its address and type
# only, because some provider IDs are credentials themselves (aws_iam_access_key). This list must
# match the Atlex server's (testdata/modeled-aws-types.json is checked on both sides).
MODELED_AWS_TYPES = frozenset(
    [
        "aws_instance",
        "aws_lambda_function",
        "aws_ecs_cluster",
        "aws_ecs_service",
        "aws_ecs_task_definition",
        "aws_ecr_repository",
        "aws_cloudwatch_log_group",
        "aws_vpc",
        "aws_subnet",
        "aws_security_group",
        "aws_lb",
        "aws_alb",
        "aws_route53_record",
        "aws_api_gateway_rest_api",
        "aws_apigatewayv2_api",
        "aws_db_instance",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_elasticache_cluster",
        "aws_iam_role",
        "aws_iam_user",
        "aws_iam_policy",
        "aws_cloudwatch_metric_alarm",
    ]
)

# A plan's JSON has these; a plan says what might change, never what's applied.
PLAN_KEYS = ("planned_values", "resource_changes", "prior_state", "configuration")

GITHUB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
REPOSITORY_ID = re.compile(r"^\d{1,20}$")
WORKSPACE = re.compile(r"^[A-Za-z0-9_.-]{1,90}$")
LINEAGE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
FORMAT_VERSION = re.compile(r"^1\.\d{1,3}$")
RESOURCE_TYPE = re.compile(r"^[a-z0-9_]{1,128}$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class ReportError(Exception):
    """A problem that stops the report before anything is sent. Messages never quote the state."""


# ── The allowlist ───────────────────────────────────────────────────────────────────────────


def provider_id(resource: Dict[str, Any]) -> Optional[str]:
    """The ARN, else the ID, of a modeled AWS type, unless the state marks it sensitive."""
    if resource.get("type") not in MODELED_AWS_TYPES:
        return None
    values = resource.get("values")
    if not isinstance(values, dict):
        return None
    sensitive = resource.get("sensitive_values")
    sensitive = sensitive if isinstance(sensitive, dict) else {}
    for key in ("arn", "id"):
        value = values.get(key)
        if not isinstance(value, str) or not value or len(value) > 2048:
            continue
        if sensitive.get(key) not in (None, False):
            continue
        return value
    return None


def strip_module(module: Dict[str, Any], counter: List[int]) -> Dict[str, Any]:
    """One module of the state, as the allowlist keeps it: managed resources' identity only."""
    out: Dict[str, Any] = {}
    address = module.get("address")
    if isinstance(address, str) and address:
        out["address"] = address
    resources = []
    for resource in module.get("resources") or []:
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            continue
        address, rtype = resource.get("address"), resource.get("type")
        if not isinstance(address, str) or not address or len(address) > 1000:
            raise ReportError("a resource in the state has no usable address")
        if not isinstance(rtype, str) or not RESOURCE_TYPE.match(rtype):
            raise ReportError("a resource in the state has no usable type")
        kept: Dict[str, Any] = {"address": address, "mode": "managed", "type": rtype}
        pid = provider_id(resource)
        if pid is not None:
            kept["values"] = {"arn" if pid == (resource.get("values") or {}).get("arn") else "id": pid}
        resources.append(kept)
        counter[0] += 1
    if resources:
        out["resources"] = resources
    children = [strip_module(c, counter) for c in module.get("child_modules") or [] if isinstance(c, dict)]
    if children:
        out["child_modules"] = children
    return out


def strip_state(state: Any) -> Dict[str, Any]:
    """`terraform show -json` of a state, down to the allowlist. Refuses a plan."""
    if not isinstance(state, dict):
        raise ReportError("`terraform show -json` didn't print a JSON object")
    if any(key in state for key in PLAN_KEYS):
        raise ReportError("that's a plan's JSON; run this after apply, on the applied state")
    version = state.get("format_version")
    if not isinstance(version, str) or not FORMAT_VERSION.match(version):
        raise ReportError("the state's format_version isn't one Atlex reads (1.x)")
    out: Dict[str, Any] = {"format_version": version}
    values = state.get("values")
    if isinstance(values, dict) and isinstance(values.get("root_module"), dict):
        counter = [0]
        out["values"] = {"root_module": strip_module(values["root_module"], counter)}
        if counter[0] > MAX_RESOURCES:
            raise ReportError(f"the state has more than {MAX_RESOURCES} resources")
    return out


def lineage_and_serial(raw_state: Any) -> "tuple[str, int]":
    """Only the serial and lineage of the raw state; nothing else of it is kept or printed."""
    if not isinstance(raw_state, dict):
        raise ReportError("`terraform state pull` didn't print a JSON object")
    lineage, serial = raw_state.get("lineage"), raw_state.get("serial")
    if not isinstance(lineage, str) or not LINEAGE.match(lineage):
        raise ReportError("the state has no usable lineage")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 0:
        raise ReportError("the state has no usable serial")
    return lineage, serial


def is_root_folder(root: str) -> bool:
    if root == ".":
        return True
    if len(root) > 500 or re.search(r"[\s\\]", root):
        return False
    return all(part not in ("", ".", "..") for part in root.split("/"))


def build_payload(
    *,
    state: Any,
    raw_state: Any,
    owner: str,
    name: str,
    repository_id: str,
    root: str,
    workspace: str,
) -> bytes:
    """The exact bytes sent (before gzip): deterministic, so `--dry-run` shows what's posted."""
    if not GITHUB_NAME.match(owner) or not GITHUB_NAME.match(name):
        raise ReportError("the repository must be owner/name, as GitHub writes it")
    if not REPOSITORY_ID.match(repository_id):
        raise ReportError("the repository ID must be GitHub's numeric ID (GITHUB_REPOSITORY_ID)")
    if not is_root_folder(root):
        raise ReportError("the root must be a folder inside the repository, like envs/prod or .")
    if not WORKSPACE.match(workspace):
        raise ReportError("the workspace name isn't one Terraform allows")
    lineage, serial = lineage_and_serial(raw_state)
    payload = {
        "format": FORMAT,
        "repository": {"owner": owner, "name": name, "id": repository_id},
        "root": root,
        "workspace": workspace,
        "lineage": lineage,
        "serial": serial,
        "state": strip_state(state),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Signing and sending ─────────────────────────────────────────────────────────────────────


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return SIGNATURE_PREFIX + mac.hexdigest()


def pack(payload: bytes) -> bytes:
    # mtime=0 so the same payload always packs to the same bytes.
    return gzip.compress(payload, mtime=0)


def send(endpoint: str, connection_id: str, secret: str, payload: bytes) -> Dict[str, Any]:
    body = pack(payload)
    if len(body) > MAX_PACKED_BYTES:
        raise ReportError("the report is over 4 MB gzipped; split the workspace or contact Atlex")
    timestamp = str(int(time.time()))
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "content-type": "application/gzip",
            "user-agent": f"atlex-tf-report/{VERSION}",
            "x-atlex-connection": connection_id,
            "x-atlex-timestamp": timestamp,
            "x-atlex-signature": sign(secret, timestamp, body),
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8")).get("data", {})


# ── Reading Terraform ───────────────────────────────────────────────────────────────────────


def run_terraform(binary: str, chdir: str, *args: str) -> str:
    try:
        done = subprocess.run(
            [binary, f"-chdir={chdir}", *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "TF_IN_AUTOMATION": "1"},
        )
    except FileNotFoundError:
        raise ReportError(f"`{binary}` isn't on the PATH; pass --terraform") from None
    if done.returncode != 0:
        # Terraform's own error text, never its stdout (which may hold the state).
        sys.stderr.write(done.stderr.decode("utf-8", "replace"))
        raise ReportError(f"`{binary} {args[0]}` failed (exit {done.returncode})")
    return done.stdout.decode("utf-8")


def read_json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise ReportError(f"{what} isn't valid JSON") from None


def read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as error:
        raise ReportError(f"can't read {path}: {error.strerror}") from None


def repo_root(chdir: str) -> Optional[str]:
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        return workspace
    try:
        done = subprocess.run(
            ["git", "-C", chdir, "rev-parse", "--show-toplevel"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None
    return done.stdout.decode("utf-8").strip() if done.returncode == 0 else None


def root_of(chdir: str) -> str:
    top = repo_root(chdir)
    if not top:
        raise ReportError("can't tell where the repository's top is; pass --root")
    rel = os.path.relpath(os.path.realpath(chdir), os.path.realpath(top))
    if rel.startswith(".."):
        raise ReportError("the Terraform folder isn't inside the repository; pass --root")
    return "." if rel == "." else rel.replace(os.sep, "/")


# ── The command ─────────────────────────────────────────────────────────────────────────────


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="atlex-tf-report", description=__doc__.split("\n\n")[0])
    p.add_argument("--chdir", default=".", help="the root module's folder (default: here)")
    p.add_argument("--terraform", default="terraform", help="the binary: terraform or tofu")
    p.add_argument("--workspace", help="the workspace (default: `terraform workspace show`)")
    p.add_argument("--root", help="the folder's path in the repository (default: worked out)")
    p.add_argument("--repository", help="owner/name (default: GITHUB_REPOSITORY)")
    p.add_argument("--repository-id", help="numeric ID (default: GITHUB_REPOSITORY_ID)")
    p.add_argument("--show-json", help="read `terraform show -json` from this file instead")
    p.add_argument("--state-file", help="read the raw state (for serial and lineage) from this file")
    p.add_argument("--endpoint", default=os.environ.get("ATLEX_ENDPOINT", DEFAULT_ENDPOINT))
    p.add_argument("--dry-run", action="store_true", help="print the payload; send nothing")
    p.add_argument("--version", action="version", version=f"atlex-tf-report {VERSION}")
    return p.parse_args(argv)


def payload_from(args: argparse.Namespace) -> bytes:
    show = (
        read_file(args.show_json)
        if args.show_json
        else run_terraform(args.terraform, args.chdir, "show", "-json")
    )
    raw = (
        read_file(args.state_file)
        if args.state_file
        else run_terraform(args.terraform, args.chdir, "state", "pull")
    )
    workspace = (
        args.workspace
        or os.environ.get("TF_WORKSPACE")
        or (
            "default"
            if args.show_json
            else run_terraform(args.terraform, args.chdir, "workspace", "show").strip()
        )
    )
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY", "")
    owner, _, name = repository.partition("/")
    repository_id = args.repository_id or os.environ.get("GITHUB_REPOSITORY_ID", "")
    if not repository or not repository_id:
        raise ReportError("set GITHUB_REPOSITORY and GITHUB_REPOSITORY_ID, or pass --repository and --repository-id")
    payload = build_payload(
        state=read_json(show, "`terraform show -json` output"),
        raw_state=read_json(raw, "the raw state"),
        owner=owner,
        name=name,
        repository_id=repository_id,
        root=args.root or root_of(args.chdir),
        workspace=workspace,
    )
    del show, raw  # the full state goes no further than this function
    return payload


def main(argv: Optional[List[str]] = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        payload = payload_from(args)
        if args.dry_run:
            out.write(payload.decode("utf-8") + "\n")
            return 0
        connection_id = os.environ.get("ATLEX_CONNECTION_ID", "")
        secret = os.environ.get("ATLEX_TF_REPORT_SECRET", "")
        if not UUID.match(connection_id):
            raise ReportError("ATLEX_CONNECTION_ID isn't set to the connection's ID")
        if not secret:
            raise ReportError("ATLEX_TF_REPORT_SECRET isn't set")
        result = send(args.endpoint, connection_id, secret, payload)
    except ReportError as error:
        err.write(f"atlex-tf-report: nothing sent: {error}\n")
        return 1
    except urllib.error.HTTPError as error:
        err.write(f"atlex-tf-report: Atlex refused the report ({error.code}): {refusal(error)}\n")
        return 2
    except (urllib.error.URLError, OSError) as error:
        err.write(f"atlex-tf-report: couldn't reach Atlex: {getattr(error, 'reason', error)}\n")
        return 1
    counts = ", ".join(f"{k} {result[k]}" for k in ("resources", "linked", "unmatched", "foreign", "dropped") if k in result)
    out.write(f"atlex-tf-report: {result.get('outcome', 'sent')}" + (f" ({counts})" if counts else "") + "\n")
    return 0


def refusal(error: urllib.error.HTTPError) -> str:
    """Atlex's error code and message: they describe the request, never echo it."""
    try:
        body = json.loads(error.read().decode("utf-8"))
        detail = body.get("error", {})
        return f"{detail.get('code', '')}: {detail.get('message', '')}".strip(": ")
    except (ValueError, AttributeError, OSError):
        return error.reason if isinstance(error.reason, str) else "no detail"
    finally:
        error.close()


if __name__ == "__main__":
    sys.exit(main())

"""Tests for atlex-tf-report (KAN-134's route, KAN-135's reporter). Standard library only:

    python3 -m unittest discover -s tf-report/tests

The fixtures in ../testdata are shared with the Atlex server's tests: the three `*.show.json` are
real `terraform show -json` output (Terraform 1.5.7 and 1.9.8, OpenTofu 1.8.8) with a planted
secret, and each `*.payload.json` is the golden payload this script must produce from it.
"""

import gzip
import hashlib
import hmac
import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TESTDATA = HERE.parent / "testdata"
sys.path.insert(0, str(HERE.parent))

import atlex_tf_report as report  # noqa: E402

SECRET_IN_STATE = "SECRET-db-pass-7f3a"
CONNECTION = "6f1c3a52-6a1e-4c55-9a0e-1f2d3c4b5a69"
SIGNING_SECRET = "a-tf-report-secret"
FIXTURES = ["terraform-1.5.7", "terraform-1.9.8", "opentofu-1.8.8", "aws"]


def args_for(fixture: str, *extra: str):
    return [
        "--show-json",
        str(TESTDATA / f"{fixture}.show.json"),
        "--state-file",
        str(TESTDATA / "raw-state.json"),
        "--repository",
        "acme/infra",
        "--repository-id",
        "4242",
        "--root",
        "envs/prod",
        "--workspace",
        "default",
        *extra,
    ]


def run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}, clear=False):
        code = report.main(argv, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class Capture(BaseHTTPRequestHandler):
    """A stand-in for Atlex: records each request and answers like /hooks/terraform."""

    requests = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["content-length"]))
        Capture.requests.append(({k.lower(): v for k, v in self.headers.items()}, body))
        if Capture.status == 200:
            reply = {"data": {"outcome": "accepted", "resources": 5, "linked": 2}}
        else:
            reply = {"error": {"code": "unauthenticated", "message": "That webhook's signature doesn't verify."}}
        data = json.dumps(reply).encode()
        self.send_response(Capture.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class AtlexStandIn:
    def __enter__(self):
        Capture.requests = []
        Capture.status = 200
        self.server = HTTPServer(("127.0.0.1", 0), Capture)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/hooks/terraform"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


SEND_ENV = {"ATLEX_CONNECTION_ID": CONNECTION, "ATLEX_TF_REPORT_SECRET": SIGNING_SECRET}


class GoldenPayloads(unittest.TestCase):
    def test_each_fixture_produces_its_golden_payload(self):
        for fixture in FIXTURES:
            with self.subTest(fixture=fixture):
                self.assertIn(SECRET_IN_STATE, (TESTDATA / f"{fixture}.show.json").read_text())
                code, out, err = run(args_for(fixture, "--dry-run"))
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(out, (TESTDATA / f"{fixture}.payload.json").read_text())
                self.assertNotIn(SECRET_IN_STATE, out)

    def test_payload_holds_only_allowlisted_fields(self):
        for fixture in FIXTURES:
            payload = json.loads((TESTDATA / f"{fixture}.payload.json").read_text())
            self.assertEqual(
                sorted(payload), ["format", "lineage", "repository", "root", "serial", "state", "workspace"]
            )
            self.assertLessEqual(set(payload["state"]), {"format_version", "values"})

            def walk(module):
                self.assertLessEqual(set(module), {"address", "resources", "child_modules"})
                for r in module.get("resources", []):
                    self.assertLessEqual(set(r), {"address", "mode", "type", "values"})
                    self.assertEqual(r["mode"], "managed")
                    if "values" in r:
                        self.assertIn(r["type"], report.MODELED_AWS_TYPES)
                        self.assertEqual(len(r["values"]), 1)
                        self.assertLessEqual(set(r["values"]), {"arn", "id"})
                for child in module.get("child_modules", []):
                    walk(child)

            walk(payload["state"].get("values", {}).get("root_module", {}))

    def test_aws_identity_is_kept_and_secrets_are_not(self):
        payload = json.loads((TESTDATA / "aws.payload.json").read_text())
        resources = payload["state"]["values"]["root_module"]["resources"]
        by_address = {r["address"]: r for r in resources}
        self.assertEqual(by_address["aws_s3_bucket.assets"]["values"], {"arn": "arn:aws:s3:::checkout-assets"})
        # An access key's ID is a credential: its type isn't modeled, so nothing but its address goes.
        self.assertNotIn("values", by_address["aws_iam_access_key.ci"])
        # A sensitive ARN falls back to the ID; a data source isn't sent at all.
        self.assertEqual(by_address["aws_instance.legacy"]["values"], {"id": "i-0abc"})
        self.assertNotIn("data.aws_caller_identity.current", by_address)
        self.assertNotIn("AKIA", json.dumps(payload))

    def test_modeled_types_match_the_shared_list(self):
        shared = json.loads((TESTDATA / "modeled-aws-types.json").read_text())
        self.assertEqual(sorted(report.MODELED_AWS_TYPES), shared)


class Sending(unittest.TestCase):
    def test_dry_run_output_is_exactly_what_is_sent(self):
        _, dry, _ = run(args_for("aws", "--dry-run"))
        with AtlexStandIn() as atlex:
            code, out, err = run(args_for("aws", "--endpoint", atlex.endpoint), SEND_ENV)
        self.assertEqual((code, err), (0, ""))
        (headers, body), = Capture.requests
        self.assertEqual(gzip.decompress(body).decode() + "\n", dry)
        self.assertEqual(headers["content-type"], "application/gzip")
        self.assertEqual(headers["x-atlex-connection"], CONNECTION)
        ts = headers["x-atlex-timestamp"]
        expected = hmac.new(SIGNING_SECRET.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["x-atlex-signature"], "v1=" + expected)
        # It reports counts, never the payload.
        self.assertIn("accepted", out)
        self.assertNotIn("aws_s3_bucket", out + err)
        self.assertNotIn(SIGNING_SECRET, out + err)

    def test_broken_input_sends_nothing(self):
        broken = TESTDATA.parent / "tests" / "broken.show.json"
        broken.write_text('{"format_version": "1.0", "values": {"root_module": {"resources": [{"mode": "managed"}]}}}')
        cases = {
            "not json": ["--show-json", str(TESTDATA / "raw-state.json") + ".missing"],
            "a resource with no address": ["--show-json", str(broken)],
        }
        try:
            with AtlexStandIn() as atlex:
                for name, override in cases.items():
                    with self.subTest(name):
                        argv = args_for("aws", "--endpoint", atlex.endpoint)
                        argv[argv.index("--show-json") + 1] = override[1]
                        code, out, err = run(argv, SEND_ENV)
                        self.assertEqual(code, 1)
                        self.assertIn("nothing sent", err)
                        self.assertEqual(out, "")
                for fixture_args, env in [
                    (args_for("aws", "--endpoint", atlex.endpoint, "--workspace", "bad name"), SEND_ENV),
                    (args_for("aws", "--endpoint", atlex.endpoint), {"ATLEX_CONNECTION_ID": "", "ATLEX_TF_REPORT_SECRET": "x"}),
                    (args_for("aws", "--endpoint", atlex.endpoint), {**SEND_ENV, "ATLEX_TF_REPORT_SECRET": ""}),
                ]:
                    code, _, err = run(fixture_args, env)
                    self.assertEqual(code, 1, err)
                self.assertEqual(Capture.requests, [])
        finally:
            broken.unlink()

    def test_a_plan_is_refused_before_anything_is_sent(self):
        with self.assertRaises(report.ReportError):
            report.strip_state({"format_version": "1.2", "planned_values": {}, "resource_changes": []})

    def test_a_refusal_exits_2_with_atlex_s_message(self):
        with AtlexStandIn() as atlex:
            Capture.status = 401
            code, out, err = run(args_for("aws", "--endpoint", atlex.endpoint), SEND_ENV)
        self.assertEqual(code, 2)
        self.assertIn("unauthenticated", err)
        self.assertNotIn("aws_s3_bucket", out + err)

    def test_errors_never_quote_the_state(self):
        with self.assertRaises(report.ReportError) as caught:
            report.lineage_and_serial({"lineage": SECRET_IN_STATE + " !", "serial": 1})
        self.assertNotIn(SECRET_IN_STATE, str(caught.exception))


class Roots(unittest.TestCase):
    def test_root_folders(self):
        for ok in [".", "envs/prod", "infra"]:
            self.assertTrue(report.is_root_folder(ok), ok)
        for bad in ["", "/abs", "a//b", "../up", "a/./b", "a/", "has space"]:
            self.assertFalse(report.is_root_folder(bad), bad)


if __name__ == "__main__":
    unittest.main()

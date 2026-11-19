# atlex-tf-report

Tells Atlex what Terraform (or OpenTofu) actually applied, so Atlex can link each live AWS resource to the Terraform resource that manages it, and later spot drift. Add it as a step right after `terraform apply`.

## What leaves your runner

Only each managed resource's identity:

| Sent | Example |
|---|---|
| The repository (owner, name, GitHub's numeric ID), the root module's folder and the workspace | `acme/infra`, `envs/prod`, `default` |
| The state's lineage and serial | `4ca3ef1c-…`, `42` |
| Each managed resource's address and type | `module.api.aws_lambda_function.handler` |
| The ARN (else the ID) of a resource Atlex models, unless your state marks it sensitive | `arn:aws:lambda:eu-west-1:111122223333:function:checkout` |

Everything else stays on the runner: every attribute value, every output, every value Terraform marks sensitive, and data sources. Only these AWS types keep an ARN or ID, so a type whose ID is itself a credential (`aws_iam_access_key`) never sends one: [`testdata/modeled-aws-types.json`](testdata/modeled-aws-types.json). Atlex applies the same allowlist again when the report arrives.

**See it yourself:** `--dry-run` (or `dry-run: true` in the Action) prints exactly the payload it would send and sends nothing. The golden payloads for real Terraform 1.5, Terraform 1.9 and OpenTofu states are in [`testdata/`](testdata/).

## GitHub Actions

Create the Terraform connection in Atlex, issue its secret, and store it as a repository or environment secret (`ATLEX_TF_REPORT_SECRET`). Then, after your apply step:

```yaml
- name: Report the applied state to Atlex
  uses: Atlex-SI/terraform-aws-atlex-connect/tf-report@<commit-sha> # pin to a commit SHA, not a tag
  with:
    connection-id: <your connection ID>
    secret: ${{ secrets.ATLEX_TF_REPORT_SECRET }}
    working-directory: envs/prod
```

Pin the Action to a full commit SHA, so what runs in your pipeline is exactly what you reviewed. Releases are tagged with the module's versions; each tag's notes give its SHA.

| Input | Default | |
|---|---|---|
| `connection-id` | | Required. |
| `secret` | | Required. From your secret store. |
| `working-directory` | `.` | The root module's folder. |
| `terraform` | `terraform` | Or `tofu`. It must already be set up and initialised. |
| `workspace` | `terraform workspace show` | |
| `dry-run` | `false` | `true` prints the payload and sends nothing. |

## Any other CI

The Action is a thin wrapper around one file, [`atlex_tf_report.py`](atlex_tf_report.py). It needs Python 3.9 or later and nothing else: it installs no packages, so that file is the whole supply chain. Run it in the root module's folder after `apply`, with your Terraform already initialised:

```sh
export ATLEX_CONNECTION_ID=<your connection ID>
export ATLEX_TF_REPORT_SECRET=<from your secret store>
export GITHUB_REPOSITORY=acme/infra        # set for you on GitHub Actions
export GITHUB_REPOSITORY_ID=123456789      # GitHub's numeric repository ID
python3 atlex_tf_report.py --chdir envs/prod
```

Use `--terraform tofu` for OpenTofu and `--root` if the folder's path in the repository can't be worked out. On an image without Python (the official `hashicorp/terraform` one), run this step in a `python:3` image with the state backend's access, or add `python3` to the image.

## How it works

1. Runs `terraform show -json` and `terraform state pull` in the folder. The raw state is read only for its serial and lineage and is never written or printed.
2. Keeps the allowlisted fields above and drops the rest. If anything doesn't parse, or the input is a plan instead of a state, it sends nothing and exits 1.
3. Gzips the payload, signs it (HMAC-SHA256 over the timestamp and the body, with your connection's secret) and posts it over HTTPS. It never prints the payload or the secret.

| Exit | Meaning |
|---|---|
| 0 | Sent, or printed for `--dry-run`. Atlex answers `accepted`, `duplicate`, `stale` (an older serial than one already reported) or `ignored`. |
| 1 | Nothing sent: a problem on this side, with the reason. |
| 2 | Atlex refused it: its reason is printed (for example a wrong secret, or reports switched off for your organisation). |

## Tests

```sh
python3 -m unittest discover -s tf-report/tests
```

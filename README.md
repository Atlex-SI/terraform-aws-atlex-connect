# terraform-aws-atlex-connect

What you install in your AWS accounts to connect them to Atlex: a read-only cross-account role with an external ID, optional EventBridge forwarding, and the `atlex-tf-report` CI step. Public so your security team can read exactly what it grants.

## atlex-tf-report

The CI step that tells Atlex what Terraform applied, stripped on your runner first: see [`tf-report/`](tf-report/README.md).

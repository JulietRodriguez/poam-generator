# GitHub Actions

## `ci.yml`: lint and tests

Runs on every push to `main` and every pull request.

| Job | What it does |
|---|---|
| `lint` | `ruff check .` |
| `test` | Installs the package with dev extras on Python 3.10, 3.11 and 3.12, downloads NIST's OSCAL 1.1.2 POA&M JSON Schema and XSD (pinned by SHA-256), runs the pytest suite with an 80% coverage floor, then generates OSCAL JSON and XML from `examples/sample_findings.json` with the CLI and validates both against the official schemas. |

## `poam-report.yml`: demo POAM artifact

Runs on pushes to `main` and manually (Actions tab → **POAM Report** → **Run workflow**).

| Job | What it does |
|---|---|
| `poam-generate` | Runs `poam demo` (CSV) and builds Excel, OSCAL JSON and OSCAL XML from the sample findings, then uploads them as the `poam-report` artifact (kept 30 days). |
| `poam-validate` | Runs `poam validate` on `examples/sample_findings.json`. |

### Why there is no weekly schedule

This workflow used to be called `poam-scan.yml` and also ran every Monday. The demo data never changes, so the weekly run rebuilt the same file each time. GitHub also disables scheduled workflows after 60 days without repository activity, which is why it showed **Disabled**. Running on push and on demand gives the same artifact without a schedule that silently stops.

To produce a POAM from live AWS Security Hub data on a schedule, run `poam sync` from a scheduled job that has AWS credentials (for example, GitHub OIDC to an IAM role with `securityhub:GetFindings`), then `poam generate`. That needs an AWS account, so it isn't set up here.

# GitHub Actions Automation

## Workflow: `poam-scan.yml`

Automates POAM generation and findings validation on every push, on a weekly schedule, and on demand.

### Triggers

| Trigger | When |
|---|---|
| `push` to `main` | Every time code lands on the main branch |
| `schedule` | Every Monday at 8:00 AM UTC |
| `workflow_dispatch` | Manually from the GitHub Actions tab |

### Jobs

#### `poam-generate` — Generate POAM Report

1. Checks out the repository
2. Sets up Python 3.11
3. Installs `poam-generator` with `pip install -e .`
4. Runs `poam demo` to produce `poam_output.csv` from the built-in demo findings
5. Uploads `poam_output.csv` as a GitHub Actions artifact named **`poam-report`** (retained for 30 days)

Download the latest report from the **Actions** tab → select a run → **Artifacts** section.

#### `poam-validate` — Validate Sample Findings

1. Checks out the repository
2. Sets up Python 3.11
3. Installs `poam-generator`
4. Runs `poam validate -i examples/sample_findings.json`
5. Exits with a non-zero code (failing the job) if any validation errors are found

This job acts as a CI gate: if someone edits `examples/sample_findings.json` in a way that breaks the schema, the workflow fails visibly before the bad data reaches any downstream process.

### Sample Findings

[`examples/sample_findings.json`](../../examples/sample_findings.json) contains 3 realistic FedRAMP/FISMA findings covering:

- **IA-5** — MFA not enforced on privileged accounts (Critical)
- **SC-28** — Unencrypted data at rest in S3 (High)
- **CM-6** — Patch management process not documented (Medium)

Use this file as a template for your own findings. All fields must match the schema validated by `poam validate`.

### Extending the Workflow

To validate your own findings file in CI, change the path in the `poam-validate` job:

```yaml
- name: Validate sample findings
  run: poam validate -i path/to/your/findings.json
```

To sync from AWS Security Hub instead of running the demo:

```yaml
- name: Sync from Security Hub
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_DEFAULT_REGION: us-east-1
  run: poam sync --source aws-security-hub --output findings.json
```

Add `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your repository's **Settings → Secrets and variables → Actions**.

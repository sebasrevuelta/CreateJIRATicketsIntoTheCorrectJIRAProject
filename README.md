# Semgrep → JIRA Ticket Automation

This project contains a Python script that automatically creates JIRA tickets from **Semgrep findings** for a subset of repositories inside a Semgrep deployment.

The script performs the following workflow:

1. Retrieves all projects from a Semgrep deployment.
2. Filters only projects whose name starts with a specific prefix (e.g. `sebasrevuelta/`).
3. Retrieves findings for each filtered project, filtered by severity and issue type via the API.
4. Creates one JIRA ticket per finding through the Semgrep Tickets API.

---

## Requirements

- Python **3.9+**
- `pip`
- A Semgrep API token
- Access to the Semgrep deployment APIs

### Python Dependencies

```bash
pip install requests
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SEMGREP_TOKEN` | Yes | Semgrep API token |
| `DEPLOYMENT_SLUG` | Yes | Your Semgrep deployment slug |
| `JIRA_PROJECT_ID` | Yes | JIRA project ID where tickets will be created (string or integer) |
| `SEMGREP_BASE_URL` | No | Defaults to `https://semgrep.dev` |

Example:

```bash
export SEMGREP_TOKEN="xxxxx"
export DEPLOYMENT_SLUG="my-deployment"
export JIRA_PROJECT_ID="12345"
```

---

## Configuration (Top of Script)

| Constant | Description |
|----------|-------------|
| `PROJECT_PREFIX` | Repository prefix filter, e.g. `sebasrevuelta/` |

---

## Running the Script

All arguments are optional. By default the script runs in dry-run mode with `sast` issue type.

```bash
# Dry run (default) — no tickets are created
python semgrep_to_jira.py

# Create tickets for SAST critical findings
python semgrep_to_jira.py --no-dry-run --issue-type sast --severities critical

# Create tickets for SCA high and critical findings on a single repo
python semgrep_to_jira.py --no-dry-run --issue-type sca --severities high critical --repo sebasrevuelta/MyRepo
```

### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--issue-type` | No | `sast` | Issue type to filter and ticket: `sast` or `sca` |
| `--severities` | No | `critical` | Severity levels to fetch. Multiple values accepted |
| `--dry-run` | No | `True` | Log actions without creating tickets (default behaviour) |
| `--no-dry-run` | No | — | Disable dry run and actually create tickets |
| `--repo` | No | — | Process a single repo instead of all prefix-matching projects |

---

## Dry Run Mode

Dry run is **enabled by default**. Pass `--no-dry-run` to actually create tickets:

```bash
# Safe — only logs what would happen
python semgrep_to_jira.py

# Live — creates tickets
python semgrep_to_jira.py --no-dry-run
```

---

## Ticket Creation Logic

One ticket is created per finding when:

- The finding matches the requested `--issue-type` and `--severities` (filtered by the API)
- The finding has a valid issue ID
- The repository matches the prefix filter
- The issue ID has not already been ticketed in the current run (in-memory de-dupe)

### POST payload fields

| Field | Value |
|-------|-------|
| `issue_type` | Value of `--issue-type` (`sast` or `sca`) |
| `issue_ids` | Single-element list with the finding's ID |
| `jira_project_id` | Value of `JIRA_PROJECT_ID` env var |

---

## API Endpoints Used

### List Projects
```
GET /api/v1/deployments/{deploymentSlug}/projects
```

### List Findings
```
GET /api/v1/deployments/{deploymentSlug}/findings?repos=<repo>&severities=<sev>&issue_type=<type>
```

### Create Ticket
```
POST /api/v1/deployments/{deploymentSlug}/tickets
```

---

## Common Pitfalls

| Problem | Cause |
|---------|-------|
| No tickets created | No findings match the given severity / issue type |
| API errors | Invalid token or deployment slug |
| Missing tickets | `DRY_RUN` is set to `True` |

---

## Summary

This automation bridges Semgrep security findings with JIRA workflows by:

- Filtering repositories by prefix
- Fetching findings filtered by severity and issue type
- Creating one structured ticket per finding automatically

It reduces manual triage effort while maintaining control and accuracy.
